# Secure Device Provisioning Service

A Go service for exercising secure device onboarding and MQTT communication across
a synthetic edge-to-cloud boundary. An administrator creates a short-lived token
bound to a device and hardware ID. The device generates its own ECDSA key and CSR,
exchanges the token for a short-lived X.509 certificate, then connects to a bounded
MQTT 3.1.1 endpoint over TLS 1.3 with mutual certificate authentication.

The repository does not use Axis devices, firmware, APIs, certificates, customer
data, or internal architecture. It is a portfolio implementation, not evidence of
production IoT fleet operation.

## Engineering scope

- Go HTTP control plane with strict JSON, request limits, server timeouts, health
  probes, structured logging, and graceful shutdown.
- Hardware-bound, single-use bootstrap tokens stored as SHA-256 digests.
- Device-generated ECDSA keys and certificate signing requests.
- Short-lived X.509 client certificates, CA chain validation, and lifecycle revocation.
- Actual TCP/TLS sockets with TLS 1.3 mutual authentication.
- Reviewable MQTT 3.1.1 subset: CONNECT, QoS 0/1 PUBLISH, PUBACK, SUBSCRIBE,
  desired-configuration delivery, PING, and DISCONNECT.
- Certificate identity, MQTT client ID, and exact per-device topic authorization.
- Synthetic edge simulator for enrollment and QoS 1 telemetry.
- Race-detector tests, coverage reporting, binary builds, Docker, Kubernetes assets,
  an AWS IoT Core policy mapping, and GitHub Actions.

## Architecture

```text
Admin -> bootstrap token -> Go control plane <- CSR/key generated on device
                              |
                              v
                     signed client certificate
                              |
Synthetic device -> MQTT 3.1.1 over mTLS -> scoped telemetry/config boundary
```

See [architecture](docs/architecture.md), [security design](docs/security.md),
[AWS/Kubernetes mapping](docs/aws-and-kubernetes.md), and
[limitations](docs/limitations.md).

## Run locally

Requires Go 1.26.5.

```powershell
go test -race -coverprofile=coverage.out ./...
go vet ./...
go build ./cmd/controlplane
go build ./cmd/device-simulator
go run ./cmd/controlplane
```

Create a bootstrap token:

```powershell
curl.exe -X POST http://127.0.0.1:8080/v1/bootstrap-tokens `
  -H "Content-Type: application/json" `
  -H "X-Admin-Key: local-admin-key-change-me" `
  -d '{"deviceId":"camera-001","hardwareId":"hardware-001","ttlSeconds":600}'
```

Pass the returned token to the synthetic device:

```powershell
$env:DEVICE_ID="camera-001"
$env:HARDWARE_ID="hardware-001"
$env:BOOTSTRAP_TOKEN="<returned-token>"
go run ./cmd/device-simulator
```

The simulator generates the private key locally, submits a CSR, validates the CA,
connects with mTLS, and publishes one synthetic QoS 1 message.

## HTTP API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health/live` | Liveness |
| `GET` | `/health/ready` | Readiness |
| `POST` | `/v1/bootstrap-tokens` | Admin creates a hardware-bound token |
| `POST` | `/v1/enroll` | Device exchanges token and CSR for certificate |
| `GET` | `/v1/devices/{id}` | Admin reads lifecycle/certificate metadata |
| `POST` | `/v1/devices/{id}/revoke` | Admin blocks the active certificate |

## Verification

```powershell
gofmt -w .
go vet ./...
go test -race ./...
go test -coverpkg=./internal/... -coverprofile=coverage.out ./internal/...
go tool cover -func=coverage.out
go build ./cmd/controlplane
go build ./cmd/device-simulator
python scripts/validate_deploy.py
```

Local verification on 30 July 2026:

- 18 automated tests passed, including integration tests over real TCP/TLS sockets
  for mutual TLS, MQTT QoS 1 acknowledgement, per-device topic authorization,
  desired configuration, revocation, and untrusted-certificate rejection.
- Internal-package statement coverage: **79.9%**, above the CI gate of 75%.
- `gofmt`, `go vet`, both binary builds, and deployment-descriptor validation passed.
- The Windows host did not have the C toolchain required by Go's local race detector,
  so `go test -race` is enforced by the Linux GitHub Actions job.
- A local Docker daemon was unavailable; the Docker image build is enforced in CI.

## Deliberate boundary

Verification replay on 16 November 2026 passed all 18 top-level tests and three
certificate-validity subtests, `go vet`, and both binary builds on Windows.
Certificate tests use an explicit clock for before/during/after-validity cases.
The negative cases also require the X.509 validity error, so an unrelated error
cannot pass as successful expiry rejection. Certificate validation in the
service is unchanged. Linux CI also runs the race detector and image build.
This assertion maintenance and its verification used Codex assistance.

This service demonstrates Go, device provisioning, PKI, TCP/TLS, MQTT, topic
authorization, Kubernetes design, and AWS IoT policy mapping. It does not claim
embedded firmware development, live AWS usage, Axis integration, production scale,
MQTT conformance, real-device interoperability, or customer impact.

## License

MIT
