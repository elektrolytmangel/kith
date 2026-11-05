// Example parameters. Copy this file, keep the copy (subscription-specific values) out of the repository.
using 'main.bicep'

param name = 'kith'
param image = 'ghcr.io/elektrolytmangel/kith-relay:0.1.0-alpha.3'

// Optional:
// param allowedIpRanges = ['203.0.113.0/24']
// param relaySettings = { KITH_RELAY_MAX_CONNECTIONS: '2000' }
// param registryServer = 'ghcr.io'
// param registryUsername = '<user>'
// param registryPassword = readEnvironmentVariable('REGISTRY_PASSWORD')
