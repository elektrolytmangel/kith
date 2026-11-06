# Deploying the relay and the always-on client

Both ship as container images on GitHub Packages (ghcr.io), built from the
release binaries (Linux, amd64 and arm64). Nothing is published anywhere else.

| Image | Contents | State |
| --- | --- | --- |
| `ghcr.io/elektrolytmangel/kith-relay` | `kith-relay`, port 8080 (plain WebSocket) | none: RAM only |
| `ghcr.io/elektrolytmangel/kith-always-on` | `kith-always-on --data /data` | the volume `/data` |

Tags are the release version without the `v` (`0.1.0-alpha.6`). `latest` exists
only for non-pre-releases. Images exist from `0.1.0-alpha.3` on.

## Relay

```sh
docker run -d --name kith-relay -p 8080:8080 --read-only \
  ghcr.io/elektrolytmangel/kith-relay:<version>
curl localhost:8080/healthz
```

The relay speaks plain WebSocket. Put TLS in front of it: clients should use
`wss://`. Limits are set through `KITH_RELAY_*` variables
(see the README).

**Serve only approved organizations:** set `KITH_RELAY_ALLOWED_ORGS` to the org IDs
(each org's root public key, hex; your app shows it as the org ID), separated by
commas. Without it the relay serves any org that presents a valid certificate chain.
Read at start: changing the list means restarting the relay. To change it without a
restart, keep the list in an Azure Table instead (`KITH_RELAY_AZURE_STORAGE_ACCOUNT`, see
[integration.md](integration.md#relay)); the relay re-reads it every 30 s and
drops the devices of an org you remove.

### On Azure

Container Apps with a managed identity and Bicep: [deployment-azure.md](deployment-azure.md).

### With TLS: Docker Compose

[`deploy/docker-compose.yml`](../../deploy/docker-compose.yml) runs the relay
behind Caddy, which gets a certificate automatically:

```sh
export KITH_VERSION=<version> DOMAIN=relay.example.com
docker compose -f deploy/docker-compose.yml up -d
```

Ports 80 and 443 must reach the host. The relay stores nothing, so there is
nothing to back up and it can be restarted or replaced at any time (clients
reconnect).

## Always-on client

A member that is always online, so others can catch up when no other device is
around. It needs a volume for its key and data, and an invite link from an
admin (create it in your app).

```sh
# first run: paste the invite link at the prompt; it joins the org and prints a
# short code to compare with the admin's screen
docker run -it --name kith-always-on -v kith-always-on:/data \
  ghcr.io/elektrolytmangel/kith-always-on:<version> --join -
```

`--join -` reads the link from stdin, so it stays out of the process list and the
shell history (the invite is a secret until it is used).

The first run keeps running after it is admitted. Stop it with `docker stop`.
Later starts need no arguments:

```sh
docker start kith-always-on
```

Or with Compose: `docker compose -f deploy/docker-compose.yml run --rm always-on --join -`,
then `docker compose -f deploy/docker-compose.yml --profile always-on up -d`.

Lose the volume and the member is gone: back it up with `--export-backup`
(passphrase in a file named by `KITH_BACKUP_PASSPHRASE_FILE`, e.g. a Docker secret;
see [integration.md](integration.md)) or re-invite.

## Publishing the images (maintainers)

`release.yml` builds and pushes them on a release tag with `GITHUB_TOKEN`; a
dry run builds without pushing. The first push creates the packages as
**private**. Once per package: on GitHub open *Packages → kith-relay →
Package settings → Change visibility → Public* (same for `kith-always-on`), so
users can pull without logging in.

To build from source instead: `docker build -f apps/relay-server/Dockerfile .`
(relay only).
