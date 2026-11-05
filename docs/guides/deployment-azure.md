# Deploy the relay on Azure Container Apps

[`deploy/azure/main.bicep`](../../deploy/azure/main.bicep) creates everything the relay needs:

| Resource | Purpose |
| --- | --- |
| Container App `<name>-relay` | the relay image, **exactly one replica** (it is an in-memory router; two would split the devices), external HTTPS ingress, health probes |
| Container Apps environment + Log Analytics | logs (`ContainerAppConsoleLogs_CL`) |
| Storage account + table `allowedorgs` | the list of approved organizations |
| User-assigned managed identity | reads and writes the relay's tables (*Storage Table Data Contributor* on each table, not on the account). The account has shared-key access disabled: no key exists |

The relay still stores nothing about your users' data. Only the approved-org list is durable.

## Prerequisites

- An Azure subscription, the [Azure CLI](https://learn.microsoft.com/cli/azure/) (`az login`), and a resource group.
- The relay image. The Linux images from a release include the Azure Table support:
  `ghcr.io/<owner>/kith-relay:<version>`. A new ghcr.io package is private until you make it public (package
  settings on GitHub); otherwise pass `registryServer`, `registryUsername`, `registryPassword`.
- The org IDs to approve (each org's root public key in hex; your app shows it as the org ID).

## Deploy

Keep your own parameter file (subscription specifics) outside this repository; start from `main.bicepparam`.

```sh
az group create -n kith-rg -l westeurope
az deployment group what-if -g kith-rg -f deploy/azure/main.bicep -p deploy/azure/main.bicepparam   # preview
az deployment group create  -g kith-rg -f deploy/azure/main.bicep -p deploy/azure/main.bicepparam \
  --query properties.outputs
```

Outputs: `relayUrl` (`wss://…/v1/ws`, give it to your app), `storageAccount`, `allowedOrgsTable`.
Check it: `curl https://<fqdn>/healthz` prints `ok`.

Parameters worth knowing: `image`, `allowedIpRanges` (CIDRs; empty allows everyone, which devices need),
`relaySettings` (any `KITH_RELAY_*` limit, see [integration.md](integration.md#relay)), `allowlistRefreshSecs`.

## Approve an organization

The table starts **empty, and an empty table approves nobody**: the relay refuses every `announce` until you add
an org. One row per org: `PartitionKey` = `org`, `RowKey` = the org ID.

```sh
# Your user needs "Storage Table Data Contributor" on the account (the deployment gives it only to the relay).
SA=$(az deployment group show -g kith-rg -n main --query properties.outputs.storageAccount.value -o tsv)
az storage entity insert --auth-mode login --account-name "$SA" --table-name allowedorgs \
  --entity PartitionKey=org RowKey=<org-id>
az storage entity delete --auth-mode login --account-name "$SA" --table-name allowedorgs \
  --partition-key org --row-key <org-id>
```

The relay re-reads the table every 30 s. Removing an org disconnects its online devices from that org
(`org-not-allowed`); they cannot announce again. If a read fails, the relay keeps the last list and logs a warning.
At start it needs a successful read, otherwise it exits (Container Apps restarts it: look at the logs for a missing
role assignment, which can take a few minutes to take effect after the first deployment).

## TLS and a custom domain

Container Apps terminates TLS on `*.azurecontainerapps.io`; WebSockets work over it (`wss://`). For your own domain,
add the DNS records first, then bind a managed certificate (the order matters, which is why the template leaves it out):

```sh
az containerapp hostname add  -g kith-rg -n kith-relay --hostname relay.example.com   # shows the DNS records to create
az containerapp hostname bind -g kith-rg -n kith-relay --hostname relay.example.com --environment kith-env --validation-method CNAME
```

## Updating, cost, limits

- **Update:** change `image` and deploy again; a new revision replaces the old one. All devices reconnect
  automatically (the client reconnects with backoff), and in-flight frames are dropped: that is normal for the relay.
- **Cost:** one replica at 0.5 vCPU / 1 GiB is always on (Container Apps cannot scale a WebSocket relay to zero without
  dropping connections), plus Log Analytics ingestion and a few cents of storage. Check the
  [Azure pricing calculator](https://azure.microsoft.com/pricing/calculator/) for your region.
- **Revocation notices** are held in RAM by default ([ADR 0013](../adr/0013-relay-revocation.md)): a relay restart
  forgets them until the issuing admin reconnects. Set `persistRevocations = true` to keep them in the `revocations`
  table ([ADR 0014](../adr/0014-optional-revocation-persistence.md)); the relay then stores the IDs of removed devices
  and their signed notices, and re-verifies them at start.
- **Deployments made before table-scoped roles:** the relay's identity used to hold *Storage Table Data Contributor*
  on the whole storage account. Deploying the current template adds the per-table assignments but does not remove
  the old one; delete it once (Azure portal: storage account → *Access control (IAM)* → *Role assignments*, or
  `az role assignment delete --assignee <principalId> --role "Storage Table Data Contributor" --scope <storage account ID>`).
- **Not covered:** the managed identity path was written against the
  documented Container Apps endpoint and is verified against the Azurite emulator only for the table calls.
