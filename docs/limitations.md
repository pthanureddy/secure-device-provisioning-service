# Evidence boundary and limitations

- No Axis device, AXIS OS, firmware, API, certificate, customer, or internal material is used.
- No physical edge device or embedded firmware is included.
- The device simulator generates synthetic identifiers and telemetry.
- No AWS resources or Kubernetes cluster were created.
- The project has not been load-tested and makes no fleet-scale or availability claim.
- The MQTT implementation is an intentionally narrow MQTT 3.1.1 subset, not a
  general broker and not a standards-conformance claim.
- DNS behavior is represented by the operating system resolver; DNS failure and
  failover testing are not included.
- The HTTP API is plaintext for local development. Put it behind an authenticated
  TLS ingress before any shared environment.
- The in-memory registry, ephemeral CA, and single process are not production architecture.

The repository demonstrates testable onboarding, certificate, TCP/TLS, MQTT, and
deployment-design concepts without presenting local simulations as professional
device-fleet experience.

