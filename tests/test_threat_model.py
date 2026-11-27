"""Structural checks for the machine-readable threat model."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_threat_model_references_existing_assets_controls_and_evidence() -> None:
    model = json.loads((ROOT / "threat-model.json").read_text(encoding="utf-8"))
    assert model["schema_version"] == "1.0"
    assert model["actors"] and model["trust_boundaries"] and model["residual_risks"]

    asset_ids = {item["id"] for item in model["assets"]}
    control_ids = {item["id"] for item in model["controls"]}
    assert len(asset_ids) == len(model["assets"])
    assert len(control_ids) == len(model["controls"])

    for boundary in model["trust_boundaries"]:
        assert set(boundary["controls"]) <= control_ids
    for threat in model["threats"]:
        assert set(threat["assets"]) <= asset_ids
        assert set(threat["controls"]) <= control_ids
        for evidence in threat.get("verification", []):
            assert (ROOT / evidence).exists(), evidence
