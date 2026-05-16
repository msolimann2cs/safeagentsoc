from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.storage.snapshots import snapshot_paths


def test_snapshot_paths_create_expected_names(tmp_path):
    paths = snapshot_paths(tmp_path, "before_sprint7")

    assert paths.snapshot_file == tmp_path / "before_sprint7.dump"
    assert paths.manifest_file == tmp_path / "before_sprint7.manifest.txt"
