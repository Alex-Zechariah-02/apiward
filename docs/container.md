# Container image

Back to the [README](../README.md).

## Build

- `Dockerfile` builds one image of the gateway with the Dashboard inside.
- Node.js 24 builds the Dashboard, Go 1.27.4 builds a static `gateway` with the `embedui` tag and cgo off, and the final image is built from `scratch`: the program, plus the certificate authority bundle, `passwd`, `group` and `nsswitch.conf` taken from the distroless static Debian 13 image.
- It runs as that image's `nonroot` user, UID and GID 65532, and has no shell, time zone data or other system files.
- Every base image is pinned by digest.
In a checkout:

```
docker build -t apiward:dev .
```

- `--build-arg REVISION=$(git rev-parse HEAD)` records the commit in the label `org.opencontainers.image.revision`.
- `docker buildx build --sbom=true --output type=local,dest=<new-folder> .` also writes the image's software bill of materials as `sbom.spdx.json`; it needs the containerd image store or a `docker-container` builder.
- No image is published to a registry.

## Files and folders

- The image runs `apiward run --config /etc/apiward/apiward.json`.
- Mount the settings, keys and certificates read-only at `/etc/apiward`, with every path in the settings under that folder.
- The only writable folder is `/var/lib/apiward`, so the settings keep the database and the security log there: mount a local named volume or host folder on it, since SQLite's write-ahead log does not work over a network file system (https://www.sqlite.org/wal.html).
- Key files must belong to UID 65532 and be readable by it alone (mode 600; for example `sudo chown -R 65532:65532 <folder>`): the gateway refuses a key that others can read.
- Secrets stay in those files, never in environment variables.

## First start

Install the first administrator once, before the first start:

```
docker run --rm -v apiward-data:/var/lib/apiward -v "$PWD/apiward:/etc/apiward:ro" apiward:dev install --config /etc/apiward/apiward.json --admin <name>
```

`install` prints a one-time enrolment secret; keep it private. It also creates the identity key `identity.pem` beside the database in `/var/lib/apiward`, unless the settings name another key or set `upstream.unsigned_identity`. Then start the gateway:

```
docker run -d --name apiward --network host --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --stop-timeout 30 \
  -v apiward-data:/var/lib/apiward -v "$PWD/apiward:/etc/apiward:ro" apiward:dev
```

- In the Dashboard choose **First Sign-In with an Enrolment Secret**, then establish the first policy.
- The image's health check runs `apiward health`, which asks the metrics listener's `/readyz`, so a new gateway reports unhealthy until its first policy is published.
- `docker stop` sends `SIGTERM`; give the gateway at least 30 seconds to stop (`--stop-timeout 30`, or `stop_grace_period: 30s` in Compose).

## Network

- The admin listener always stays on loopback and is never published, so the image runs on the host's network (`--network host`) on Linux with Docker Engine.
- The Dashboard is then on the host's `127.0.0.1`; from another machine, reach it through `ssh -N -L 9440:127.0.0.1:9440 <user>@<host>` with the same port on both ends, since the browser's `Host` must equal the admin listen address.
- The listeners use the addresses and ports of the settings: `-p` is ignored with host networking, and no address translation sits in the request path.
- Docker Desktop offers host networking only as an opt-in setting (version 4.34 or later, Settings > Resources > Network, signed in to Docker), at layer 4 and without binding the host's IP addresses, so it is not the documented setup.

The Fetch repository's `compose.yaml` runs this image beside the Fetch services on one Linux host, with settings its demo tool writes; its `docs/hosts.md`, "Containers", walks through a complete first run.
