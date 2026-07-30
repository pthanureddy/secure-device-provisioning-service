# Architecture

## Purpose

The service demonstrates the control-plane and device-side boundaries involved in
secure onboarding. It exchanges a one-time bootstrap secret and a device-generated
certificate signing request for a short-lived X.509 client certificate, then uses
that identity for MQTT 3.1.1 communication over TLS 1.3.

```text
Admin / manufacturing record
        |
        | create hardware-bound bootstrap token
        v
Go HTTP control plane <---- CSR generated on synthetic edge device
        |
        | signed client certificate + CA + scoped topics
        v
Synthetic device ---- mTLS / MQTT ---- Go broker boundary
        |                                   |
        | QoS 1 status/telemetry            | receipt metadata
        | desired configuration <-----------+
```

## Modules

- `internal/pki`: ECDSA development CA, CSR validation, client/server certificates.
- `internal/provisioning`: token lifecycle, hardware binding, enrollment records,
  revocation, and certificate-to-device authorization.
- `internal/mqtt`: bounded MQTT wire codec, mTLS broker, topic authorization, QoS 1
  telemetry receipt, desired-configuration delivery, and test client.
- `internal/api`: strict JSON HTTP API, admin boundary, error mapping, and probes.
- `cmd/controlplane`: HTTP/MQTT startup, timeouts, structured logs, and shutdown.
- `cmd/device-simulator`: local key/CSR generation, enrollment, and one telemetry publish.

## Deliberate choices

The broker implements only the MQTT 3.1.1 behavior required to test this boundary:
clean-session CONNECT, QoS 0/1 PUBLISH, one QoS 0 SUBSCRIBE, PING, and DISCONNECT.
Packet size, topic scope, TLS version, and deadlines are bounded. A production
service should use a maintained broker or AWS IoT Core rather than extend this codec.

The registry is in memory to keep certificate and protocol behavior inspectable.
Durable, highly available fleet state requires a transactional store, migrations,
replication, and idempotent event processing.

