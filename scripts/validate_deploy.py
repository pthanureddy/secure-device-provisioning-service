from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load_yaml_documents(path: Path) -> list[dict[str, object]]:
    with path.open(encoding="utf-8") as stream:
        documents = [item for item in yaml.safe_load_all(stream) if item is not None]
    if not documents:
        raise ValueError(f"{path} contains no Kubernetes objects")
    for document in documents:
        if not isinstance(document, dict):
            raise ValueError(f"{path} contains a non-object YAML document")
        metadata = document.get("metadata")
        if not document.get("apiVersion") or not document.get("kind"):
            raise ValueError(f"{path} object is missing apiVersion or kind")
        if not isinstance(metadata, dict) or not metadata.get("name"):
            raise ValueError(f"{path} object is missing metadata.name")
    return documents


def validate_kubernetes() -> None:
    documents: list[dict[str, object]] = []
    for path in sorted((ROOT / "deploy" / "kubernetes").glob("*.yaml")):
        documents.extend(load_yaml_documents(path))
    kinds = {str(document["kind"]) for document in documents}
    required = {"Deployment", "Service", "NetworkPolicy", "Secret"}
    if not required.issubset(kinds):
        raise ValueError(f"missing Kubernetes kinds: {sorted(required - kinds)}")
    deployment = next(item for item in documents if item["kind"] == "Deployment")
    spec = deployment["spec"]
    if not isinstance(spec, dict) or spec.get("replicas") != 1:
        raise ValueError("development Deployment must remain single-replica")
    pod_spec = spec["template"]["spec"]
    container = pod_spec["containers"][0]
    security = container["securityContext"]
    if not pod_spec.get("automountServiceAccountToken") is False:
        raise ValueError("service-account token must stay disabled")
    if not security.get("readOnlyRootFilesystem") or security.get(
        "allowPrivilegeEscalation"
    ):
        raise ValueError("container security settings are incomplete")
    if not container.get("livenessProbe") or not container.get("readinessProbe"):
        raise ValueError("health probes are required")


def validate_aws_policy() -> None:
    policy_path = ROOT / "deploy" / "aws-iot-policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    actions = {
        action
        for statement in policy["Statement"]
        for action in statement.get("Action", [])
    }
    required = {"iot:Connect", "iot:Publish", "iot:Subscribe", "iot:Receive"}
    if actions != required:
        raise ValueError(f"unexpected AWS IoT actions: {sorted(actions)}")
    resources = [
        resource
        for statement in policy["Statement"]
        for resource in statement.get("Resource", [])
    ]
    if any("${iot:Connection.Thing.ThingName}" not in item for item in resources):
        raise ValueError("every AWS IoT resource must be scoped to the Thing identity")


if __name__ == "__main__":
    validate_kubernetes()
    validate_aws_policy()
    print("deployment descriptors validated")

