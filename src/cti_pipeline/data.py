"""Dataset loaders with a shared canonical schema.

Canonical per-flow columns
--------------------------
src_ip, dst_ip, src_port, dst_port, proto, ts (epoch seconds), label (0/1),
attack_cat  -- required for the CTI replay.
All remaining dataset-native columns are kept as model features.
"""

from __future__ import annotations

import re
from pathlib import Path

import numpy as np
import pandas as pd

CANON_REQUIRED = [
    "src_ip", "dst_ip", "src_port", "dst_port", "proto", "ts", "label", "attack_cat",
]
DROP_FROM_FEATURES = {
    "src_ip", "dst_ip", "src_port", "dst_port", "ts", "label", "attack_cat",
}

UNSW_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes",
    "sttl", "dttl", "sloss", "dloss", "service", "Sload", "Dload", "Spkts", "Dpkts",
    "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth",
    "res_bdy_len", "Sjit", "Djit", "Stime", "Ltime", "Sintpkt", "Dintpkt", "tcprtt",
    "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd",
    "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm",
    "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "attack_cat", "label",
]

_TS_FORMATS = ["%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M"]


def _epoch_seconds(ts: pd.Series) -> pd.Series:
    """datetime64 -> float epoch seconds (NaT -> NaN).

    pandas 3 refuses ``Series.astype("float64")`` on datetimes, so convert
    through int64 nanoseconds first.
    """
    arr = ts.to_numpy(dtype="datetime64[ns]")
    values = arr.view("int64").astype("float64") / 1e9
    values[np.isnat(arr)] = np.nan
    return pd.Series(values, index=ts.index)


def _clean_strings(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [str(c).strip().replace("﻿", "") for c in df.columns]
    for col in df.select_dtypes(include=["object", "string"]).columns:
        df[col] = df[col].astype("string").str.strip()
    return df


def _downcast(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    for col in cols:
        if col in df.columns and pd.api.types.is_numeric_dtype(df[col]):
            df[col] = pd.to_numeric(df[col], downcast="integer")
            if pd.api.types.is_float_dtype(df[col]):
                df[col] = pd.to_numeric(df[col], downcast="float")
    return df


def _stratified_subsample(df: pd.DataFrame, max_rows: int, seed: int) -> pd.DataFrame:
    if max_rows <= 0 or len(df) <= max_rows:
        return df
    frac = max_rows / len(df)
    parts = []
    for _, grp in df.groupby("label", observed=True):
        take = max(1, int(round(len(grp) * frac)))
        parts.append(grp.sample(n=min(take, len(grp)), random_state=seed))
    out = pd.concat(parts, axis=0).sample(frac=1.0, random_state=seed)
    return out


# --------------------------------------------------------------------------
# UNSW-NB15 (full 4-part release: has srcip/dstip + Stime/Ltime epochs)
# --------------------------------------------------------------------------
def load_unsw_nb15(directory: str | Path, max_rows: int = 0, seed: int = 42) -> pd.DataFrame:
    directory = Path(directory)
    files = sorted(directory.glob("UNSW-NB15_[1-4].csv"))
    if not files:
        raise FileNotFoundError(f"UNSW-NB15 part files not found under {directory}")
    frames = [
        pd.read_csv(f, header=None, names=UNSW_COLUMNS, encoding="latin-1", low_memory=False)
        for f in files
    ]
    df = pd.concat(frames, axis=0, ignore_index=True)
    df = _clean_strings(df)

    out = pd.DataFrame(index=df.index)
    out["src_ip"] = df["srcip"].astype("string")
    out["dst_ip"] = df["dstip"].astype("string")
    out["src_port"] = pd.to_numeric(df["sport"], errors="coerce")
    out["dst_port"] = pd.to_numeric(df["dsport"], errors="coerce")
    out["proto"] = df["proto"].astype("string").fillna("unk")
    out["ts"] = pd.to_numeric(df["Stime"], errors="coerce")
    out["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype("int8")
    out["attack_cat"] = df["attack_cat"].fillna("Normal").astype("string")

    drop_dup = {"srcip", "dstip", "sport", "dsport", "Stime", "label", "attack_cat", "proto"}
    keep = [c for c in df.columns if c not in drop_dup]
    out = pd.concat([out, df[keep]], axis=1)
    out = _downcast(out, [c for c in out.columns if c not in {"src_ip", "dst_ip", "proto", "attack_cat"}])
    out = out.dropna(subset=["ts"]).reset_index(drop=True)
    out = _stratified_subsample(out, max_rows, seed)
    return out.sort_values("ts", kind="mergesort").reset_index(drop=True)


# --------------------------------------------------------------------------
# CICIDS2017 GeneratedLabelledFlows (has Source/Destination IP + Timestamp)
# --------------------------------------------------------------------------
def load_cicids2017(directory: str | Path, max_rows: int = 0, seed: int = 42) -> pd.DataFrame:
    directory = Path(directory)
    files = sorted(directory.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"CICIDS2017 CSVs not found under {directory}")
    frames = [pd.read_csv(f, low_memory=False, encoding="latin-1") for f in files]
    df = pd.concat(frames, axis=0, ignore_index=True)
    df = _clean_strings(df)

    rename = {
        "Source IP": "src_ip", "Destination IP": "dst_ip",
        "Source Port": "src_port", "Destination Port": "dst_port",
        "Protocol": "proto", "Timestamp": "ts", "Label": "attack_cat",
    }
    df = df.rename(columns=rename)
    if "Flow ID" in df.columns:
        df = df.drop(columns=["Flow ID"])

    ts = pd.to_datetime(df["ts"], errors="coerce", format=_TS_FORMATS[0])
    for fmt in _TS_FORMATS[1:]:
        if ts.isna().any():
            ts = ts.fillna(pd.to_datetime(df["ts"], errors="coerce", format=fmt))
    out = pd.DataFrame(index=df.index)
    out["src_ip"] = df["src_ip"].astype("string")
    out["dst_ip"] = df["dst_ip"].astype("string")
    out["src_port"] = pd.to_numeric(df["src_port"], errors="coerce")
    out["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce")
    out["proto"] = pd.to_numeric(df["proto"], errors="coerce").astype("Int64").astype("string")
    out["ts"] = _epoch_seconds(ts)
    out["attack_cat"] = df["attack_cat"].astype("string")
    # pandas StringDtype comparisons propagate NA -> fill before casting to int8
    out["label"] = out["attack_cat"].ne("BENIGN").fillna(False).astype("int8")
    out.loc[out["attack_cat"].isna(), "label"] = 0
    out.loc[out["label"] == 0, "attack_cat"] = "Normal"
    out.loc[out["label"] == 1, "attack_cat"] = out.loc[out["label"] == 1, "attack_cat"].str.replace(
        r"\s*$/,.*", "", regex=True
    ).str.strip()

    skip = {"src_ip", "dst_ip", "src_port", "dst_port", "proto", "ts", "attack_cat", "label"}
    rest = [c for c in df.columns if c not in skip]
    num = [c for c in rest if pd.api.types.is_numeric_dtype(df[c])]
    out = pd.concat([out, df[num]], axis=1)
    out = _downcast(out, num)
    out = out.dropna(subset=["ts"]).reset_index(drop=True)
    out = _stratified_subsample(out, max_rows, seed)
    return out.sort_values("ts", kind="mergesort").reset_index(drop=True)


LOADERS = {"unsw_nb15": load_unsw_nb15, "cicids2017": load_cicids2017}


def load_sighting_frame(name: str, directory: str | Path) -> pd.DataFrame:
    """Full (never subsampled) [src_ip, dst_ip, ts, label] frame.

    Feed visibility must be derived from *all* traffic - subsampling the
    benchmark would otherwise erase the repeat sightings that make an IoC
    visible to a polling feed.
    """
    directory = Path(directory)
    if name == "unsw_nb15":
        files = sorted(directory.glob("UNSW-NB15_[1-4].csv"))
        usecols = [0, 2, 28, 48]  # srcip, dstip, Stime, label
        cols = ["src_ip", "dst_ip", "ts", "label"]
        frames = [pd.read_csv(f, header=None, usecols=usecols, names=cols,
                              encoding="latin-1") for f in files]
    elif name == "cicids2017":
        files = sorted(directory.glob("*.csv"))
        frames = []
        for f in files:
            head = pd.read_csv(f, nrows=0, encoding="latin-1")
            wanted = {"Source IP", "Destination IP", "Timestamp", "Label"}
            usecols = [c for c in head.columns if c.strip() in wanted]
            part = pd.read_csv(f, usecols=usecols, encoding="latin-1", low_memory=False)
            part.columns = [c.strip() for c in part.columns]
            part = part.rename(columns={"Source IP": "src_ip", "Destination IP": "dst_ip",
                                        "Timestamp": "ts", "Label": "label"})
            frames.append(part)
    else:
        raise KeyError(name)

    df = pd.concat(frames, axis=0, ignore_index=True)
    if name == "cicids2017":
        ts = pd.to_datetime(df["ts"], errors="coerce", format=_TS_FORMATS[0])
        for fmt in _TS_FORMATS[1:]:
            if ts.isna().any():
                ts = ts.fillna(pd.to_datetime(df["ts"], errors="coerce", format=fmt))
        df["ts"] = _epoch_seconds(ts)
        df["label"] = (df["label"].astype("string").str.strip()
                       .ne("BENIGN").fillna(False).astype("int8"))
    else:
        df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
        df["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype("int8")
    for col in ("src_ip", "dst_ip"):
        df[col] = df[col].astype("string").str.strip()
    return df.dropna(subset=["ts"]).reset_index(drop=True)


def load_dataset(name: str, directory: str | Path, max_rows: int = 0, seed: int = 42) -> pd.DataFrame:
    if name not in LOADERS:
        raise KeyError(f"unknown dataset {name!r}; known: {sorted(LOADERS)}")
    df = LOADERS[name](directory, max_rows=max_rows, seed=seed)
    df["dataset"] = name
    return df


# --------------------------------------------------------------------------
# Feature design matrix
# --------------------------------------------------------------------------
def _pool_categories(series: pd.Series, min_freq: float, floor: int = 50) -> pd.Series:
    counts = series.value_counts(dropna=False)
    keep = set(counts[counts >= max(min_freq * len(series), floor)].index)
    return series.where(series.isin(keep), "OTHER").astype("string").fillna("UNK")


def build_design(
    df: pd.DataFrame,
    include_cti: bool,
    cti_cols: list[str] | None = None,
    rare_rate: float = 0.001,
    pool_floor: int = 50,
) -> tuple[pd.DataFrame, np.ndarray]:
    """Return (X, y). One-hot encodes low-cardinality categoricals (proto/service/state/flag)."""
    cti_cols = cti_cols or []
    label = df["label"].to_numpy()
    drop = set(DROP_FROM_FEATURES)
    if not include_cti:
        drop |= set(cti_cols)

    cat_cols = [
        c for c in df.columns
        if c not in drop and c != "dataset" and not pd.api.types.is_numeric_dtype(df[c])
        and not pd.api.types.is_bool_dtype(df[c])
    ]
    num_cols = [
        c for c in df.columns
        if c not in drop and c != "dataset" and c not in cat_cols
        and pd.api.types.is_numeric_dtype(df[c])
        and c not in ("index",)
    ]

    frames: list[pd.DataFrame] = []
    if num_cols:
        frames.append(df[num_cols].astype("float64"))
    for col in cat_cols:
        pooled = _pool_categories(df[col], rare_rate, floor=pool_floor)
        dummies = pd.get_dummies(pooled, prefix=col, dtype=np.float32)
        frames.append(dummies)

    X = pd.concat(frames, axis=1) if len(frames) > 1 else frames[0]
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return X, label
