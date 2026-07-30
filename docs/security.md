# Security design and threat boundaries

## Implemented controls

- 256-bit random, SHA-256-digested bootstrap tokens with a one-hour maximum lifetime.
- Token binding to both device ID and synthetic hardware ID.
- Single-use token exchange guarded by a mutex.
- Device-generated ECDSA key and CSR; the control plane never receives the private key.
- CSR signature and common-name validation.
- Short-lived X.509 client certificates with client-auth extended key usage.
- TLS 1.3 and mandatory client-certificate validation on the MQTT listener.
- Certificate serial and device lifecycle checks after TLS chain validation.
- MQTT client ID bound to certificate common name.
- Exact per-device publish and subscribe topic scopes.
- Strict JSON decoding, one-megabyte request limit, server timeouts, and admin-key boundary.
- Container and Kubernetes non-root/read-only settings and a default network policy.

## Production work

- Store CA keys in an HSM or managed private CA; never generate an ephemeral CA per pod.
- Add certificate rotation, revocation distribution, overlap windows, and recovery flows.
- Replace the simple admin key with workload identity and auditable authorization.
- Persist token/device state transactionally and protect it with encryption and backups.
- Add rate limiting, anti-replay evidence, manufacturing trust, ownership transfer,
  tenant isolation, monitoring, incident response, and security review.
- Validate protocol behavior with a maintained MQTT broker, network fault injection,
  interoperability tests, and representative edge firmware.

This project contains no Axis keys, protocols, devices, firmware, customer data, or
internal architecture.

