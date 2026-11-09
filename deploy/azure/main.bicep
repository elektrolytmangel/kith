// kith relay on Azure Container Apps, with the approved-orgs list in Azure Table Storage.
// Scope: resource group.   az deployment group create -g <rg> -f main.bicep -p main.bicepparam
// Guide: docs/guides/deployment-azure.md

@description('Prefix for all resource names (3-12 lowercase letters or digits).')
@minLength(3)
@maxLength(12)
param name string = 'kith'

param location string = resourceGroup().location

@description('Relay image. The Linux images from the release include the Azure Table state.')
param image string = 'ghcr.io/elektrolytmangel/kith-relay:0.2.0-beta.3'

@description('Credentials for a private registry. Leave empty for a public ghcr.io package.')
param registryServer string = ''
param registryUsername string = ''
@secure()
param registryPassword string = ''

@description('Table that holds the approved org IDs (one row per org: PartitionKey "org", RowKey = org ID).')
param allowedOrgsTable string = 'allowedorgs'

@description('Serve every organization (default): the approved-org table is not created or read. Set false to approve orgs one by one. For apps that create an org per room (REQ-RELAY-009). The abuse limits still apply.')
param openOrgs bool = true

@description('Keep revocation notices in a table so a relay restart does not forget them (ADR 0014). Set false for RAM only.')
param persistRevocations bool = true

@description('How often the relay re-reads the table, in seconds.')
param allowlistRefreshSecs int = 30

@description('CIDR ranges allowed to reach the relay. Empty allows everyone (devices connect from anywhere).')
param allowedIpRanges array = []

@description('Extra relay settings, e.g. { KITH_RELAY_MAX_CONNECTIONS: \'2000\' }. See docs/guides/integration.md.')
param relaySettings object = {}

param cpu string = '0.5'
param memory string = '1Gi'

@description('Days to keep logs.')
param logRetentionDays int = 30

var suffix = uniqueString(resourceGroup().id)
// 0a9a7e1f-...: built-in role "Storage Table Data Contributor"
var tableContributor = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3')
var usePrivateRegistry = !empty(registryServer)

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${name}-logs'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: logRetentionDays
  }
}

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${name}-relay'
  location: location
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: take('${name}${suffix}', 24)
  location: location
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    // The relay uses its managed identity; no account key is ever handed out.
    allowSharedKeyAccess: false
  }
}

resource tables 'Microsoft.Storage/storageAccounts/tableServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

resource allowedOrgs 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = if (!openOrgs) {
  parent: tables
  name: allowedOrgsTable
}

resource revocations 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = if (persistRevocations) {
  parent: tables
  name: 'revocations'
}

// The relay's identity gets data access to its two tables only, not to the
// whole storage account (it never creates tables or touches other data).
resource relayCanUseAllowedOrgs 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!openOrgs) {
  scope: allowedOrgs
  name: guid(allowedOrgs.id, identity.id, tableContributor)
  properties: {
    roleDefinitionId: tableContributor
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource relayCanUseRevocations 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (persistRevocations) {
  scope: revocations
  name: guid(revocations.id, identity.id, tableContributor)
  properties: {
    roleDefinitionId: tableContributor
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource env 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${name}-env'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logs.properties.customerId
        sharedKey: logs.listKeys().primarySharedKey
      }
    }
  }
}

// clientId is only known at deployment time, so the fixed settings are a literal array.
var relayEnv = [
  { name: 'KITH_RELAY_ADDR', value: '0.0.0.0:8080' }
  { name: 'KITH_RELAY_AZURE_STORAGE_ACCOUNT', value: storage.name }
  // The ingress proxy appends the client address; count connections per client, not per proxy.
  { name: 'KITH_RELAY_CLIENT_IP_HEADER', value: 'x-forwarded-for' }
  { name: 'AZURE_CLIENT_ID', value: identity.properties.clientId }
]

var allowlistEnv = openOrgs ? [{ name: 'KITH_RELAY_OPEN_ORGS', value: 'true' }] : [
  { name: 'KITH_RELAY_AZURE_ALLOWED_ORGS_TABLE', value: allowedOrgsTable }
  { name: 'KITH_RELAY_ALLOWLIST_REFRESH_SECS', value: string(allowlistRefreshSecs) }
]
var persistEnv = persistRevocations ? [{ name: 'KITH_RELAY_PERSIST_REVOCATIONS', value: 'true' }] : []
var extraEnv = [for item in items(relaySettings): { name: item.key, value: item.value }]

resource relay 'Microsoft.App/containerApps@2024-03-01' = {
  name: '${name}-relay'
  location: location
  // The table roles must exist before the relay starts, or its first read fails and it exits.
  dependsOn: [relayCanUseAllowedOrgs, relayCanUseRevocations, allowedOrgs, revocations]
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${identity.id}': {} }
  }
  properties: {
    managedEnvironmentId: env.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 8080
        transport: 'auto' // WebSocket upgrades work over HTTP/1.1
        allowInsecure: false
        ipSecurityRestrictions: [for (cidr, i) in allowedIpRanges: {
          name: 'allow-${i}'
          action: 'Allow'
          ipAddressRange: cidr
        }]
      }
      registries: usePrivateRegistry ? [
        {
          server: registryServer
          username: registryUsername
          passwordSecretRef: 'registry-password'
        }
      ] : []
      secrets: usePrivateRegistry ? [
        { name: 'registry-password', value: registryPassword }
      ] : []
    }
    template: {
      containers: [
        {
          name: 'relay'
          image: image
          resources: { cpu: json(cpu), memory: memory }
          env: concat(relayEnv, allowlistEnv, persistEnv, extraEnv)
          probes: [
            {
              type: 'Liveness'
              httpGet: { path: '/healthz', port: 8080 }
              periodSeconds: 30
            }
            {
              type: 'Readiness'
              httpGet: { path: '/healthz', port: 8080 }
              periodSeconds: 10
            }
          ]
        }
      ]
      // One replica only: the relay is an in-memory router, a second one would split the devices.
      scale: { minReplicas: 1, maxReplicas: 1 }
    }
  }
}

output relayUrl string = 'wss://${relay.properties.configuration.ingress.fqdn}/v1/ws'
output storageAccount string = storage.name
output allowedOrgsTable string = allowedOrgsTable
