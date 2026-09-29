"""Task 1 regression tests: robust repo-clone/job workspace.

Covers the exact failure mode observed live:
`git clone` into a job dir containing a stale/partial `repo/` directory
fails with "could not write config file .git/config: Permission denied"
because git cannot overwrite the locked config inside the stale tree.
The fix guarantees a fresh destination on every attempt.
"""

from pathlib import Path

from ecdat.persistence import store as store_module
from ecdat.persistence.store import _clone_repo, _remove_tree_quietly


def test_clone_into_stale_repo_dir_starts_fresh(tmp_path, monkeypatch) -> None:
    """A stale repo/ dir (simulated partial clone) must not break cloning."""
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    stale = job_dir / "repo"
    stale.mkdir()
    (stale / ".git").mkdir()
    (stale / ".git" / "config").write_text("[core]\n\trepositoryformatversion = 0\n")
    (stale / "leftover.txt").write_text("stale partial clone")

    calls: list[list[str]] = []
    real_run = store_module.subprocess.run

    def _fake_run(command, **kwargs):
        calls.append(list(command))
        dest = Path(command[-1])
        # Simulate git behaviour: fail if the destination already exists
        # with content (the real-world Permission denied), succeed on fresh.
        if dest.exists() and any(dest.iterdir()):
            raise AssertionError(
                f"clone attempted into non-fresh directory: {dest}")
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "cloned.txt").write_text("ok")

        class _Completed:
            returncode = 0
            stderr = ""
            stdout = ""
        return _Completed()

    monkeypatch.setattr(store_module.subprocess, "run", _fake_run)
    try:
        result = _clone_repo(job_dir, "https://example.com/repo.git")
    finally:
        monkeypatch.setattr(store_module.subprocess, "run", real_run)
    assert result.is_dir()
    assert (result / "cloned.txt").exists()
    assert not (job_dir / "repo" / "leftover.txt").exists()


def test_failed_clone_cleans_up_partial_dir(tmp_path, monkeypatch) -> None:
    """A failed clone must not leave a partial repo/ behind for the retry."""
    job_dir = tmp_path / "job"
    job_dir.mkdir()

    class _Failed:
        returncode = 128
        stderr = "fatal: repository not found"
        stdout = ""

    def _fail_run(command, **kwargs):
        Path(command[-1]).mkdir(parents=True, exist_ok=True)
        return _Failed()

    monkeypatch.setattr(store_module.subprocess, "run", _fail_run)
    try:
        try:
            _clone_repo(job_dir, "https://example.com/missing.git")
        except Exception:
            pass
        else:
            raise AssertionError("expected _clone_repo to raise")
    finally:
        import subprocess as _real_subprocess

        monkeypatch.setattr(store_module.subprocess, "run",
                            _real_subprocess.run)
    assert not (job_dir / "repo").exists()


def test_remove_tree_quietly_never_raises(tmp_path) -> None:
    _remove_tree_quietly(tmp_path / "does-not-exist")
    target = tmp_path / "file.txt"
    target.write_text("x")
    _remove_tree_quietly(target)
    assert not target.exists()
