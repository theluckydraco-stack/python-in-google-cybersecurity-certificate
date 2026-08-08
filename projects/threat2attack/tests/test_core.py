from pathlib import Path

from threat2attack.core import approve_demo_mappings, candidate_mappings, load_observations, write_outputs


def test_candidate_mapping_requires_review(tmp_path: Path) -> None:
    observations = load_observations(Path("examples/observations.json"))
    mappings = candidate_mappings(observations)

    assert mappings
    assert all(item["review"]["status"] == "pending" for item in mappings)

    write_outputs(mappings, tmp_path)
    assert not list((tmp_path / "sigma").glob("*.yml"))
    assert not list((tmp_path / "kql").glob("*.kql"))
    assert not list((tmp_path / "spl").glob("*.spl"))


def test_approved_demo_emits_detection_drafts(tmp_path: Path) -> None:
    observations = load_observations(Path("examples/observations.json"))
    mappings = candidate_mappings(observations)
    approve_demo_mappings(mappings)
    write_outputs(mappings, tmp_path)

    assert list((tmp_path / "sigma").glob("*.yml"))
    assert list((tmp_path / "kql").glob("*.kql"))
    assert list((tmp_path / "spl").glob("*.spl"))
    assert (tmp_path / "attack-navigator-layer.json").exists()
