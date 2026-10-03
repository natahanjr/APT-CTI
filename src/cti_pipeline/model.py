"""Model training, threshold tuning and metrics (Random Forest backbone)."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, train_test_split


def _m(cfg):
    """Accept either a full Config or a ModelConfig."""
    return cfg.model if hasattr(cfg, "model") else cfg


@dataclass
class Splits:
    train: np.ndarray
    val: np.ndarray
    test: np.ndarray


def make_splits(y: np.ndarray, test_size: float = 0.2, val_size: float = 0.2,
                seed: int = 42) -> Splits:
    idx = np.arange(len(y))
    trainval, test = train_test_split(idx, test_size=test_size, random_state=seed,
                                      stratify=y)
    rel_val = val_size / (1.0 - test_size)
    train, val = train_test_split(trainval, test_size=rel_val, random_state=seed,
                                  stratify=y[trainval])
    return Splits(train=np.asarray(train), val=np.asarray(val), test=np.asarray(test))


def make_model(cfg) -> RandomForestClassifier:
    m = _m(cfg)
    return RandomForestClassifier(
        n_estimators=m.n_estimators,
        min_samples_leaf=m.min_samples_leaf,
        max_features="sqrt",
        n_jobs=m.n_jobs,
        random_state=m.seed,
        class_weight="balanced_subsample",
    )


def tune_threshold(y_true: np.ndarray, proba: np.ndarray, target_recall: float) -> float:
    """Largest threshold whose recall still meets ``target_recall`` on validation."""
    precision, recall, thresholds = precision_recall_curve(y_true, proba)
    if thresholds.size == 0:
        return 0.5
    mask = recall[:-1] >= target_recall
    if not mask.any():
        return float(thresholds[recall[:-1].argmax()])
    return float(thresholds[mask].max())


def metrics_at(y_true: np.ndarray, proba: np.ndarray, theta: float) -> dict:
    pred = (proba >= theta).astype(int)
    tn = int(((pred == 0) & (y_true == 0)).sum())
    fp = int(((pred == 1) & (y_true == 0)).sum())
    fn = int(((pred == 0) & (y_true == 1)).sum())
    tp = int(((pred == 1) & (y_true == 1)).sum())
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "accuracy": float(accuracy_score(y_true, pred)),
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "f1": float(f1_score(y_true, pred, zero_division=0)),
        "pr_auc": float(average_precision_score(y_true, proba)),
        "roc_auc": float(roc_auc_score(y_true, proba)),
        "fpr": float(fpr),
        "theta": float(theta),
        "tn": tn, "fp": fp, "fn": fn, "tp": tp,
        "n": int(len(y_true)),
        "n_alerts": int(pred.sum()),
    }


def _at(X, idx):
    return X.iloc[idx] if hasattr(X, "iloc") else X[idx]


def fit_and_score(X_train, y_train, X_tune, y_tune, X_test, y_test, cfg,
                  target_recall: float | None = None) -> tuple[RandomForestClassifier, dict]:
    """Fit on train, tune theta on tune-set (matched recall), score on test."""
    target = _m(cfg).target_recall if target_recall is None else target_recall
    model = make_model(cfg)
    model.fit(X_train, y_train)
    proba_tune = model.predict_proba(X_tune)[:, 1]
    theta = tune_threshold(y_tune, proba_tune, target)
    proba_test = model.predict_proba(X_test)[:, 1]
    return model, metrics_at(y_test, proba_test, theta)


def cross_validate(X, y, cfg, target_recall: float | None = None) -> tuple[list[dict], RandomForestClassifier]:
    """5-fold stratified CV; theta tuned inside each fold (no test leakage)."""
    m = _m(cfg)
    target = m.target_recall if target_recall is None else target_recall
    skf = StratifiedKFold(n_splits=m.cv_folds, shuffle=True, random_state=m.seed)
    fold_metrics: list[dict] = []
    last_model = None
    for fold, (tr, te) in enumerate(skf.split(X, y), start=1):
        tr_rel, va = train_test_split(tr, test_size=0.2, random_state=m.seed,
                                      stratify=y[tr])
        model = make_model(cfg)
        model.fit(_at(X, tr_rel), y[tr_rel])
        theta = tune_threshold(y[va], model.predict_proba(_at(X, va))[:, 1], target)
        m_fold = metrics_at(y[te], model.predict_proba(_at(X, te))[:, 1], theta)
        m_fold["fold"] = fold
        fold_metrics.append(m_fold)
        last_model = model
        print(f"    fold {fold}: acc={m_fold['accuracy']:.4f} f1={m_fold['f1']:.4f} "
              f"fpr={m_fold['fpr']:.5f} recall={m_fold['recall']:.3f} "
              f"pr_auc={m_fold['pr_auc']:.4f}", flush=True)
    return fold_metrics, last_model


def aggregate(folds: list[dict]) -> dict:
    keys = ["accuracy", "precision", "recall", "f1", "pr_auc", "roc_auc", "fpr"]
    out = {}
    for k in keys:
        vals = np.array([f[k] for f in folds], dtype="float64")
        out[f"{k}_mean"] = float(vals.mean())
        out[f"{k}_std"] = float(vals.std(ddof=1)) if len(vals) > 1 else 0.0
    out["n_folds"] = len(folds)
    return out
