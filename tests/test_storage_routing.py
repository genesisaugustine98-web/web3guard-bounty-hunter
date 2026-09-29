from pathlib import Path

import pytest

from web3guard.storage.base import StorageError
from web3guard.storage.routing import StorageRouter


def test_default_storage_routes_are_distinct(tmp_path: Path):
    router = StorageRouter.from_config(tmp_path, {})
    paths = {
        router.findings_db_path.resolve(),
        router.cost_db_path.resolve(),
        router.cache_path.resolve(),
        router.durable_db_path.resolve(),
    }
    assert len(paths) == 4
    assert router.findings_db_path.name == "findings.db"
    assert router.cost_db_path.name == "cost.db"
    assert router.cache_path.name == "llm_cache.db"
    assert router.durable_db_path.name == "durable.db"


def test_storage_paths_block_collisions(tmp_path: Path):
    cfg = {
        "storage": {
            "paths": {
                "findings_db_path": ".web3guard/shared.db",
                "durable_db_path": ".web3guard/shared.db",
            }
        }
    }
    with pytest.raises(StorageError, match="routing collision"):
        StorageRouter.from_config(tmp_path, cfg)


def test_storage_paths_can_be_overridden(tmp_path: Path):
    cfg = {
        "storage": {
            "paths": {
                "findings_db_path": "data/findings.sqlite",
                "cost_db_path": "data/cost.sqlite",
                "cache_path": "cache/llm.sqlite",
                "durable_db_path": "state/durable.sqlite",
                "reports_dir": "artifacts/reports",
            }
        }
    }
    router = StorageRouter.from_config(tmp_path, cfg)
    assert router.findings_db_path == tmp_path / "data/findings.sqlite"
    assert router.cost_db_path == tmp_path / "data/cost.sqlite"
    assert router.cache_path == tmp_path / "cache/llm.sqlite"
    assert router.durable_db_path == tmp_path / "state/durable.sqlite"
    assert router.reports_dir == tmp_path / "artifacts/reports"


def test_required_remote_needs_a_dsn(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("SUPABASE_DB_URL", raising=False)
    monkeypatch.delenv("POSTGRES_DSN", raising=False)
    with pytest.raises(StorageError, match="storage.remote=required"):
        StorageRouter.from_config(tmp_path, {"storage": {"remote": "required"}})


def test_remote_auto_reports_environment_without_logging_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("SUPABASE_DB_URL", "postgresql://user:secret@example.supabase.co/db")
    router = StorageRouter.from_config(tmp_path, {})
    info = router.describe()
    assert info["remote"]["configured"] is True
    assert info["remote"]["dsn_env"] == "SUPABASE_DB_URL"
    assert "secret" not in str(info)
