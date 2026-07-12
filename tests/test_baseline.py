from tool_scan.baseline import Baseline


def test_new_baseline_suppresses_nothing():
    assert Baseline().is_suppressed("t1", "hash1") is False


def test_approved_entry_suppresses_matching_hash():
    baseline = Baseline()
    baseline.approve("t1", "hash1", reviewer_note="reviewed", approved_date="2026-07-11")
    assert baseline.is_suppressed("t1", "hash1") is True


def test_changed_content_hash_is_not_suppressed():
    baseline = Baseline()
    baseline.approve("t1", "hash1", reviewer_note="reviewed", approved_date="2026-07-11")
    assert baseline.is_suppressed("t1", "hash2") is False


def test_save_and_load_round_trip(tmp_path):
    baseline = Baseline()
    baseline.approve("t1", "hash1", reviewer_note="reviewed", approved_date="2026-07-11")
    path = tmp_path / "baseline.json"
    baseline.save(path)

    loaded = Baseline.load(path)
    assert loaded.is_suppressed("t1", "hash1") is True


def test_load_missing_file_returns_empty_baseline(tmp_path):
    loaded = Baseline.load(tmp_path / "missing.json")
    assert loaded.is_suppressed("t1", "hash1") is False
