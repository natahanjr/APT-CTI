"""Configuration for the CTI pipeline (defaults + optional YAML override)."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


@dataclass
class DataConfig:
    unsw_dir: str = r"C:\Users\Haaraphel\IDS_PROJECT\data"
    cic_dir: str = str(ROOT / "data" / "cicids2017" / "raw")
    datasets: list[str] = field(default_factory=lambda: ["unsw_nb15", "cicids2017"])
    max_rows: int = 600_000  # stratified subsample cap (0 = keep everything)
    test_size: float = 0.2
    val_size: float = 0.2  # fraction of the *train* split used for tuning


@dataclass
class CtiConfig:
    feeds: list[str] = field(default_factory=lambda: ["urlhaus", "threatfox", "feodo", "otx", "misp"])
    poll_interval_min: int = 5
    ttl_hours: float = 168.0
    freshness_half_life_h: float = 6.0
    db_path: str = str(ROOT / "data" / "ioc_store.db")
    snapshot_dir: str = str(ROOT / "data" / "feed_snapshots")
    otx_api_key: str = ""
    misp_url: str = ""
    misp_key: str = ""
    request_timeout_s: int = 30


@dataclass
class ReplayConfig:
    intervals_min: list[float] = field(default_factory=lambda: [1, 5, 60, 360, 1440])
    injection: str = "controlled"  # "controlled" (ground-truth IoCs) | "none"
    injection_rate: float = 0.6    # share of malicious-flow IPs published as IoCs
    benign_ioc_rate: float = 0.004  # feed noise: share of benign-only IPs flagged
    ttl_hours: float = 168.0
    freshness_half_life_h: float = 6.0
    seed: int = 42


@dataclass
class ModelConfig:
    n_estimators: int = 300
    min_samples_leaf: int = 20
    n_jobs: int = -1
    target_recall: float = 0.96
    cv_folds: int = 5
    shap_sample: int = 4000
    top_k_reasons: int = 3
    seed: int = 42


@dataclass
class Config:
    data: DataConfig = field(default_factory=DataConfig)
    cti: CtiConfig = field(default_factory=CtiConfig)
    replay: ReplayConfig = field(default_factory=ReplayConfig)
    model: ModelConfig = field(default_factory=ModelConfig)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_config(path: str | Path | None = None) -> Config:
    """Build a Config from defaults, optionally overridden by a YAML file."""
    cfg = Config()
    if path is None:
        candidate = ROOT / "config" / "default.yaml"
        path = candidate if candidate.exists() else None
    if path is None:
        return cfg
    import yaml

    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    path_keys = {"unsw_dir", "cic_dir", "db_path", "snapshot_dir"}
    for section, values in raw.items():
        if not hasattr(cfg, section) or not isinstance(values, dict):
            continue
        target = getattr(cfg, section)
        for key, value in values.items():
            if not hasattr(target, key):
                continue
            if key in path_keys and isinstance(value, str):
                candidate = Path(value)
                if not candidate.is_absolute():
                    candidate = ROOT / value
                value = str(candidate)
            setattr(target, key, value)
    return cfg
