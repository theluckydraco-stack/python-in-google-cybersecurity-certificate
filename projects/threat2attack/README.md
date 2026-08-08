# threat2attack

A review-first detection-engineering pipeline that turns structured threat-intelligence observations into candidate MITRE ATT&CK mappings, draft Sigma/SIEM detections, and ATT&CK Navigator coverage output.

## Why this project exists

Threat reports describe adversary behaviour, but moving from prose to production detection is not a one-step automation problem. `threat2attack` treats machine output as a proposal and keeps analyst validation as an explicit gate.

Pipeline:

```text
Threat report / CTI
      |
      v
Normalized observations + evidence
      |
      v
Candidate ATT&CK mappings
      |
      +--> analyst approves / rejects / edits
      |
      v
Detection hypotheses
      |
      +--> draft Sigma rules
      +--> draft KQL / SPL queries
      |
      v
Validation + tuning
      |
      v
ATT&CK Navigator coverage layer
```

## MVP scope

The first version intentionally starts with a structured JSON observation format instead of claiming reliable free-form NLP extraction. It supports:

- evidence-preserving threat observations;
- candidate Enterprise ATT&CK technique/sub-technique mappings;
- confidence and rationale attached to every mapping;
- explicit `pending`, `approved`, and `rejected` analyst states;
- Sigma rule drafts generated only from approved mappings with detection hints;
- draft Microsoft Sentinel KQL and Splunk SPL translations for the MVP event model;
- ATT&CK Navigator layer JSON showing approved detection coverage;
- deterministic local execution suitable for tests and CI.

The project should later add STIX 2.1/TAXII ingestion, LLM-assisted extraction behind a provider interface, pySigma-based backend conversion, and richer telemetry schemas.

## Data model

Each observation preserves the source evidence that justified a mapping:

```json
{
  "id": "obs-001",
  "source": "Example threat report",
  "evidence": "The actor executed PowerShell with an encoded command.",
  "platform": "windows",
  "behaviour": "powershell encoded command execution",
  "detection": {
    "logsource": "process_creation",
    "product": "windows",
    "field": "CommandLine",
    "contains": ["powershell", "-enc"]
  }
}
```

## Quick start

```bash
cd projects/threat2attack
python3 -m threat2attack.cli examples/observations.json --out build
```

Outputs:

```text
build/
  mappings.json
  sigma/
  kql/
  spl/
  attack-navigator-layer.json
```

By default, generated mappings are `pending`. To demonstrate the full pipeline, use `--auto-approve-demo`; this flag exists only for synthetic examples and must not be used as a production validation shortcut.

```bash
python3 -m threat2attack.cli examples/observations.json --out build --auto-approve-demo
```

## Validation boundary

A technique tag is not evidence that a detection is effective. Approval should confirm at least:

1. the quoted CTI evidence actually supports the ATT&CK mapping;
2. the chosen telemetry can observe the behaviour;
3. the rule fields exist in the target data source;
4. expected benign activity and false positives are documented;
5. the detection is tested against representative positive and negative events.

## ATT&CK and Sigma sources

The project is designed around MITRE's official ATT&CK STIX data and the SigmaHQ rule specification. ATT&CK data should be version-pinned for reproducible builds, while update automation can raise a review when a newer release becomes available.

## Status

MVP scaffold. The code currently demonstrates the control flow and review boundary with a small built-in mapping catalogue. It is not yet a production threat-intelligence parser or production detection compiler.
