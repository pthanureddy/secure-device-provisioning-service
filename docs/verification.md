# Verification record

Verified on 30 July 2026 against commit
[`89e1f8d`](https://github.com/pthanureddy/secure-device-provisioning-service/commit/89e1f8ddf30e220df2b91b9efc6a094b930fad5e).

## Public CI

[GitHub Actions run 30577262211](https://github.com/pthanureddy/secure-device-provisioning-service/actions/runs/30577262211)
completed successfully:

- Linux `gofmt` and `go vet`
- `go test -race ./...`
- 18 automated tests
- 79.9% internal-package statement coverage against a 75% gate
- control-plane and device-simulator binary builds
- Kubernetes and AWS IoT descriptor checks
- Docker image build

## Integration boundaries exercised

The integration tests open actual TCP/TLS sockets and exercise:

- TLS 1.3 mutual certificate authentication
- certificate identity to MQTT client-ID binding
- MQTT 3.1.1 CONNECT and QoS 1 PUBLISH/PUBACK
- exact per-device topic authorization
- desired-configuration subscription and delivery
- rejected revoked and untrusted certificates
- broker shutdown while a client is connected

The tests use synthetic devices and an in-memory CA. They do not establish
production fleet scale, Axis interoperability, live AWS operation, or embedded
firmware experience.
