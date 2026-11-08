// Example parameters. Copy this file, keep the copy (subscription-specific values) out of the repository.
using 'main.bicep'

param name = 'kith'
param image = 'ghcr.io/elektrolytmangel/kith-relay:0.2.0-beta.1'

// Revocation notices are kept in the `revocations` table (default). Set false for RAM only.
param persistRevocations = true

// Serve every organization (apps that create an org per room). The approved-org table is not created or read.
// param openOrgs = true

// Optional:
// param allowedIpRanges = ['203.0.113.0/24']
// param relaySettings = { KITH_RELAY_MAX_CONNECTIONS: '2000' }
// param registryServer = 'ghcr.io'
// param registryUsername = '<user>'
// param registryPassword = readEnvironmentVariable('REGISTRY_PASSWORD')
