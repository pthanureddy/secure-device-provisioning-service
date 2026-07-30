# AWS and Kubernetes mapping

`deploy/aws-iot-policy.json` is a reviewable AWS IoT Core policy template. It maps
the same certificate-bound identity to:

- an MQTT client ID matching the IoT Thing name;
- publish access to that device's telemetry and status topics;
- subscribe/receive access to that device's desired-configuration topic.

The file is syntax-checked in CI but has not been applied to an AWS account. A real
deployment must create Things, certificates, policies, ownership/tenant mappings,
rotation workflows, logs, alarms, and region-specific data controls.

`deploy/kubernetes` contains a single-replica development Deployment, Service,
NetworkPolicy, and example Secret. CI parses the resources and verifies expected
kinds, single-replica scope, probes, and container security invariants.
The pod uses non-root execution, a read-only filesystem, dropped capabilities,
resource bounds, probes, no service-account token, and restricted ingress/egress.

The current binary creates an in-memory CA and registry at startup, so scaling this
manifest beyond one replica would be incorrect. Production Kubernetes work requires
external PKI, durable state, a managed MQTT endpoint, pod disruption policy,
availability zones, autoscaling signals, and rollout/rollback procedures.
