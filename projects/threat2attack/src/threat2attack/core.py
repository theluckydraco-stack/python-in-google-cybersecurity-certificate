from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import yaml


CATALOGUE: list[dict[str, Any]] = [
    {
        "technique_id": "T1059.001",
        "technique": "PowerShell",
        "tactic": "execution",
        "platforms": {"windows"},
        "keywords": {"powershell", "encoded", "command", "-enc"},
    },
    {
        "technique_id": "T1105",
        "technique": "Ingress Tool Transfer",
        "tactic": "command-and-control",
        "platforms": {"windows", "linux", "macos"},
        "keywords": {"download", "curl", "wget", "transfer", "payload", "tool"},
    },
]


def load_observations(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("input must be a JSON array of observations")
    required = {"id", "source", "evidence", "platform", "behaviour"}
    for item in data:
        missing = required - item.keys()
        if missing:
            raise ValueError(f"observation {item.get('id', '<unknown>')} missing: {sorted(missing)}")
    return data


def candidate_mappings(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for observation in observations:
        haystack = f"{observation['evidence']} {observation['behaviour']}".lower()
        tokens = {token.strip(".,:;()[]{}\"'") for token in haystack.split()}
        platform = observation["platform"].lower()

        for technique in CATALOGUE:
            hits = sorted(keyword for keyword in technique["keywords"] if keyword in tokens)
            if platform not in technique["platforms"] or not hits:
                continue
            confidence = min(0.95, 0.45 + 0.12 * len(hits))
            results.append(
                {
                    "observation_id": observation["id"],
                    "source": observation["source"],
                    "evidence": observation["evidence"],
                    "technique_id": technique["technique_id"],
                    "technique": technique["technique"],
                    "tactic": technique["tactic"],
                    "confidence": round(confidence, 2),
                    "rationale": f"matched behaviour terms: {', '.join(hits)}",
                    "review": {"status": "pending", "reviewer": None, "notes": None},
                    "detection": observation.get("detection"),
                }
            )
    return results


def approve_demo_mappings(mappings: list[dict[str, Any]]) -> None:
    for mapping in mappings:
        mapping["review"] = {
            "status": "approved",
            "reviewer": "synthetic-demo",
            "notes": "Automatically approved only for the bundled synthetic demonstration.",
        }


def _sigma_rule(mapping: dict[str, Any]) -> dict[str, Any] | None:
    detection = mapping.get("detection")
    if mapping["review"]["status"] != "approved" or not detection:
        return None

    field = detection["field"]
    contains = detection.get("contains", [])
    selection_key = f"{field}|contains|all" if len(contains) > 1 else f"{field}|contains"
    selection_value: Any = contains if len(contains) > 1 else contains[0]
    rule_id = str(uuid5(NAMESPACE_URL, f"threat2attack:{mapping['observation_id']}:{mapping['technique_id']}"))

    return {
        "title": f"Draft - {mapping['technique']} behaviour from CTI",
        "id": rule_id,
        "status": "experimental",
        "description": mapping["evidence"],
        "references": [mapping["source"]],
        "tags": [f"attack.{mapping['tactic']}", f"attack.{mapping['technique_id'].lower()}"],
        "logsource": {
            "category": detection["logsource"],
            "product": detection["product"],
        },
        "detection": {
            "selection": {selection_key: selection_value},
            "condition": "selection",
        },
        "falsepositives": ["Unknown; requires environment-specific validation and tuning"],
        "level": "medium",
    }


def _queries(mapping: dict[str, Any]) -> tuple[str, str] | None:
    detection = mapping.get("detection")
    if mapping["review"]["status"] != "approved" or not detection:
        return None
    field = detection["field"]
    values = detection.get("contains", [])
    kql_terms = " and ".join(f'{field} contains "{value}"' for value in values)
    spl_terms = " AND ".join(f'{field}="*{value}*"' for value in values)
    return (
        f"// DRAFT: validate table and field mappings before deployment\nSecurityEvent\n| where {kql_terms}\n",
        f"# DRAFT: validate index, sourcetype and field mappings before deployment\nsearch {spl_terms}\n",
    )


def write_outputs(mappings: list[dict[str, Any]], out_dir: Path) -> None:
    sigma_dir = out_dir / "sigma"
    kql_dir = out_dir / "kql"
    spl_dir = out_dir / "spl"
    for directory in (out_dir, sigma_dir, kql_dir, spl_dir):
        directory.mkdir(parents=True, exist_ok=True)

    (out_dir / "mappings.json").write_text(json.dumps(mappings, indent=2), encoding="utf-8")

    approved_techniques: set[str] = set()
    for mapping in mappings:
        sigma_rule = _sigma_rule(mapping)
        queries = _queries(mapping)
        if sigma_rule is None or queries is None:
            continue
        stem = f"{mapping['observation_id']}_{mapping['technique_id'].replace('.', '_')}"
        (sigma_dir / f"{stem}.yml").write_text(
            yaml.safe_dump(sigma_rule, sort_keys=False), encoding="utf-8"
        )
        (kql_dir / f"{stem}.kql").write_text(queries[0], encoding="utf-8")
        (spl_dir / f"{stem}.spl").write_text(queries[1], encoding="utf-8")
        approved_techniques.add(mapping["technique_id"])

    layer = {
        "name": "threat2attack approved detection coverage",
        "versions": {"navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Approved mappings with generated detection drafts. Coverage is not efficacy.",
        "techniques": [
            {"techniqueID": technique_id, "score": 1, "comment": "Approved mapping; draft detection generated"}
            for technique_id in sorted(approved_techniques)
        ],
    }
    (out_dir / "attack-navigator-layer.json").write_text(
        json.dumps(layer, indent=2), encoding="utf-8"
    )
