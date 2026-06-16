from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping

from honeypot_ai.endpoint import FEATURE_NAMES, EndpointWindow, feature_vector, window_to_record


LEGACY_MODEL_KIND = "river-half-space-trees"
MODEL_KIND = "endpoint-window-anomaly"
MODEL_VERSION = "endpoint-window-v2"
SCORER_AUTO = "auto"
SCORER_RIVER = "river-half-space-trees"
SCORER_ISOLATION_RAW = "isolation-forest-raw"
SCORER_ISOLATION_LOG1P = "isolation-forest-log1p"
SUPPORTED_SCORERS = (SCORER_AUTO, SCORER_RIVER, SCORER_ISOLATION_LOG1P)
AUTO_SELECTION_AUC_MARGIN = 0.005
HIGH_SEVERITY_QUANTILE = 0.995
THRESHOLD_OBJECTIVE_BEST_F1 = "best-f1"
THRESHOLD_OBJECTIVE_TARGET_FPR = "target-fpr"
THRESHOLD_OBJECTIVE_TARGET_ALERTS_PER_DAY = "target-alerts-per-day"
SUPPORTED_THRESHOLD_OBJECTIVES = (
    THRESHOLD_OBJECTIVE_BEST_F1,
    THRESHOLD_OBJECTIVE_TARGET_FPR,
    THRESHOLD_OBJECTIVE_TARGET_ALERTS_PER_DAY,
)
DEFAULT_TARGET_FPR = 0.1
DEFAULT_TARGET_ALERTS_PER_DAY = 50.0

# Features that deterministically define the weak label in endpoint.weak_label().
# Feeding these to the model leaks the label, so leakage-free evaluation excludes them.
LABEL_DEFINING_FEATURES = (
    "suricata_alerts",
    "reverse_shells",
    "persistence_attempts",
    "download_commands",
    "hash_count",
    "scanner_commands",
    "privilege_changes",
    "sensitive_file_writes",
    "download_tool_execs",
)


def behavioral_feature_names() -> tuple[str, ...]:
    """Feature names with the weak-label-defining features removed."""
    label_features = set(LABEL_DEFINING_FEATURES)
    return tuple(name for name in FEATURE_NAMES if name not in label_features)


def _resolve_feature_names(feature_names: Iterable[str] | None) -> tuple[str, ...]:
    if feature_names is None:
        return FEATURE_NAMES
    resolved = tuple(feature_names)
    if not resolved:
        raise ValueError("feature_names must contain at least one feature")
    unknown = [name for name in resolved if name not in FEATURE_NAMES]
    if unknown:
        raise ValueError(f"unknown feature names: {', '.join(unknown)}")
    return resolved


@dataclass(frozen=True)
class ModelTrainingResult:
    model_id: str
    model_path: Path
    metadata_path: Path
    threshold: float
    high_threshold: float
    training_rows: int
    selected_scorer: str
    metrics: Mapping[str, float | int | str]


@dataclass(frozen=True)
class MLAlert:
    id: str
    model_id: str
    endpoint: str
    role: str
    window_start: datetime
    window_end: datetime
    score: float
    threshold: float
    severity: str
    reasons: tuple[str, ...]
    features: Mapping[str, float]
    created_at: datetime


def train_model(
    windows: Iterable[EndpointWindow],
    model_dir: str | Path,
    *,
    threshold_quantile: float = 0.95,
    seed: int = 42,
    scorer: str = SCORER_AUTO,
    calibration_windows: Iterable[EndpointWindow] | None = None,
    threshold_objective: str | None = None,
    target_fpr: float = DEFAULT_TARGET_FPR,
    target_alerts_per_day: float = DEFAULT_TARGET_ALERTS_PER_DAY,
) -> ModelTrainingResult:
    window_list = list(windows)
    if not window_list:
        raise ValueError("cannot train ML model with an empty endpoint-window dataset")
    if not 0.0 < threshold_quantile <= 1.0:
        raise ValueError("threshold_quantile must be in the range (0, 1]")
    requested_scorer = _normalize_scorer(scorer)

    import joblib
    import numpy as np
    from river import anomaly, compose, preprocessing
    from sklearn.ensemble import IsolationForest
    from sklearn.metrics import precision_recall_curve, precision_recall_fscore_support, roc_auc_score
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import FunctionTransformer

    train_windows = [window for window in window_list if window.label != "malicious"] or window_list
    labels = np.array([1 if window.label == "malicious" else 0 for window in window_list], dtype=int)
    has_binary_labels = len(set(int(label) for label in labels)) == 2
    metrics: dict[str, float | int | str] = {
        "rows": len(window_list),
        "training_rows": len(train_windows),
        "threshold_quantile": threshold_quantile,
        "requested_scorer": requested_scorer,
    }
    candidate_models: dict[str, object] = {}
    candidate_thresholds: dict[str, float] = {}
    candidate_high_thresholds: dict[str, float] = {}
    candidate_train_scores: dict[str, object] = {}

    river_model = compose.Pipeline(
        preprocessing.MinMaxScaler(),
        anomaly.HalfSpaceTrees(n_trees=25, height=8, window_size=max(16, min(250, len(train_windows))), seed=seed),
    )
    for window in train_windows:
        river_model.learn_one(feature_vector(window))

    river_scores = np.array([float(river_model.score_one(feature_vector(window))) for window in window_list], dtype=float)
    river_train_scores = np.array(
        [float(river_model.score_one(feature_vector(window))) for window in train_windows],
        dtype=float,
    )
    river_threshold = max(float(np.quantile(river_train_scores, threshold_quantile)), 0.05)
    river_high_threshold = _high_threshold(river_train_scores, river_threshold)
    candidate_models[SCORER_RIVER] = river_model
    candidate_thresholds[SCORER_RIVER] = river_threshold
    candidate_high_thresholds[SCORER_RIVER] = river_high_threshold
    candidate_train_scores[SCORER_RIVER] = river_train_scores
    _add_score_metrics(
        metrics,
        "river",
        river_scores,
        labels,
        threshold=river_threshold,
        high_threshold=river_high_threshold,
        roc_auc_score=roc_auc_score if has_binary_labels else None,
        precision_recall_fscore_support=precision_recall_fscore_support if has_binary_labels else None,
    )

    matrix = np.array([[feature_vector(window)[name] for name in FEATURE_NAMES] for window in train_windows], dtype=float)
    all_matrix = np.array([[feature_vector(window)[name] for name in FEATURE_NAMES] for window in window_list], dtype=float)
    if len(train_windows) >= 2:
        raw_isolation = IsolationForest(random_state=seed, contamination="auto")
        raw_isolation.fit(matrix)
        raw_isolation_scores = -raw_isolation.decision_function(all_matrix)
        raw_isolation_train_scores = -raw_isolation.decision_function(matrix)
        raw_isolation_threshold = float(np.quantile(raw_isolation_train_scores, threshold_quantile))
        raw_isolation_high_threshold = _high_threshold(raw_isolation_train_scores, raw_isolation_threshold)
        _add_score_metrics(
            metrics,
            "isolation",
            raw_isolation_scores,
            labels,
            threshold=raw_isolation_threshold,
            high_threshold=raw_isolation_high_threshold,
            roc_auc_score=roc_auc_score if has_binary_labels else None,
            precision_recall_fscore_support=precision_recall_fscore_support if has_binary_labels else None,
        )

        isolation_log1p = make_pipeline(
            FunctionTransformer(np.log1p, validate=False),
            IsolationForest(random_state=seed, contamination="auto"),
        )
        isolation_log1p.fit(matrix)
        isolation_log1p_scores = -isolation_log1p.decision_function(all_matrix)
        isolation_log1p_train_scores = -isolation_log1p.decision_function(matrix)
        isolation_log1p_threshold = float(np.quantile(isolation_log1p_train_scores, threshold_quantile))
        isolation_log1p_high_threshold = _high_threshold(isolation_log1p_train_scores, isolation_log1p_threshold)
        candidate_models[SCORER_ISOLATION_LOG1P] = isolation_log1p
        candidate_thresholds[SCORER_ISOLATION_LOG1P] = isolation_log1p_threshold
        candidate_high_thresholds[SCORER_ISOLATION_LOG1P] = isolation_log1p_high_threshold
        candidate_train_scores[SCORER_ISOLATION_LOG1P] = isolation_log1p_train_scores
        _add_score_metrics(
            metrics,
            "isolation_log1p",
            isolation_log1p_scores,
            labels,
            threshold=isolation_log1p_threshold,
            high_threshold=isolation_log1p_high_threshold,
            roc_auc_score=roc_auc_score if has_binary_labels else None,
            precision_recall_fscore_support=precision_recall_fscore_support if has_binary_labels else None,
        )
    else:
        metrics["isolation_baseline"] = "skipped: fewer than two training rows"
        metrics["isolation_log1p_baseline"] = "skipped: fewer than two training rows"

    selected_scorer = _select_scorer(requested_scorer, candidate_models, metrics)
    selected_model = candidate_models[selected_scorer]
    threshold = candidate_thresholds[selected_scorer]
    high_threshold = candidate_high_thresholds[selected_scorer]
    metrics["selected_scorer"] = selected_scorer
    metrics["selected_threshold"] = threshold
    metrics["selected_high_threshold"] = high_threshold
    metrics["trained_scorers"] = ",".join(candidate_models)

    threshold_source = "training_quantile"
    if calibration_windows is not None and threshold_objective is not None:
        objective = _normalize_threshold_objective(threshold_objective)
        cal_windows = list(calibration_windows)
        if cal_windows:
            cal_scores = np.array(_score_many(cal_windows, selected_model, selected_scorer), dtype=float)
            cal_labels = np.array([1 if window.label == "malicious" else 0 for window in cal_windows], dtype=int)
            has_binary_cal_labels = len(set(int(label) for label in cal_labels)) == 2
            choice = _select_calibration_threshold(
                cal_scores,
                cal_labels,
                cal_windows,
                fallback_threshold=threshold,
                threshold_objective=objective,
                target_fpr=target_fpr,
                target_alerts_per_day=target_alerts_per_day,
                has_binary_calibration_labels=has_binary_cal_labels,
                precision_recall_curve=precision_recall_curve,
            )
            threshold = float(choice["selected_threshold"])
            threshold_source = str(choice["threshold_source"])
            selected_train_scores = candidate_train_scores.get(selected_scorer)
            if selected_train_scores is not None:
                high_threshold = _high_threshold(selected_train_scores, threshold)
            metrics["threshold_objective"] = objective
            metrics["threshold_source"] = threshold_source
            metrics["calibration_rows"] = len(cal_windows)
            metrics["target_fpr"] = target_fpr
            metrics["target_alerts_per_day"] = target_alerts_per_day
            metrics["selected_threshold"] = threshold
            metrics["selected_high_threshold"] = high_threshold

    model_id = _model_id(window_list, seed)
    output_dir = Path(model_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / "model.joblib"
    metadata_path = output_dir / "metadata.json"
    artifact = {
        "kind": MODEL_KIND,
        "version": MODEL_VERSION,
        "model_id": model_id,
        "selected_scorer": selected_scorer,
        "model": selected_model,
        "feature_names": FEATURE_NAMES,
        "threshold": threshold,
        "high_threshold": high_threshold,
        "threshold_source": threshold_source,
    }
    joblib.dump(artifact, model_path)
    metadata = {
        "model_id": model_id,
        "kind": MODEL_KIND,
        "version": MODEL_VERSION,
        "selected_scorer": selected_scorer,
        "trained_at": _now().isoformat(),
        "feature_names": list(FEATURE_NAMES),
        "threshold": threshold,
        "high_threshold": high_threshold,
        "threshold_source": threshold_source,
        "training_rows": len(train_windows),
        "dataset_rows": len(window_list),
        "metrics": metrics,
        "model_path": str(model_path),
    }
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return ModelTrainingResult(
        model_id=model_id,
        model_path=model_path,
        metadata_path=metadata_path,
        threshold=threshold,
        high_threshold=high_threshold,
        training_rows=len(train_windows),
        selected_scorer=selected_scorer,
        metrics=metrics,
    )


def train_calibrated_model(
    windows: Iterable[EndpointWindow],
    model_dir: str | Path,
    *,
    threshold_objective: str = THRESHOLD_OBJECTIVE_BEST_F1,
    calibration_fraction: float = 0.2,
    threshold_quantile: float = 0.95,
    target_fpr: float = DEFAULT_TARGET_FPR,
    target_alerts_per_day: float = DEFAULT_TARGET_ALERTS_PER_DAY,
    seed: int = 42,
    scorer: str = SCORER_AUTO,
    min_year: int | None = 2000,
) -> ModelTrainingResult:
    """Train a model whose deployed threshold is calibrated on a temporal holdout.

    The most recent ``calibration_fraction`` of windows is held out; the model is
    fit on the earlier windows and the deployed threshold is selected on the
    holdout using ``threshold_objective`` instead of the training-score quantile.
    """
    objective = _normalize_threshold_objective(threshold_objective)
    if not 0.0 < calibration_fraction < 1.0:
        raise ValueError("calibration_fraction must be in the range (0, 1)")
    ordered = sorted(
        [window for window in windows if min_year is None or window.window_start.year >= min_year],
        key=lambda item: (item.window_start, item.window_end, item.endpoint, item.role, item.id),
    )
    if len(ordered) < 2:
        raise ValueError("cannot calibrate a deployed threshold with fewer than two endpoint windows")
    split_index = max(1, min(len(ordered) - 1, int(len(ordered) * (1.0 - calibration_fraction))))
    fit_pool = ordered[:split_index]
    calibration_windows = ordered[split_index:]
    return train_model(
        fit_pool,
        model_dir,
        threshold_quantile=threshold_quantile,
        seed=seed,
        scorer=scorer,
        calibration_windows=calibration_windows,
        threshold_objective=objective,
        target_fpr=target_fpr,
        target_alerts_per_day=target_alerts_per_day,
    )


def load_model(path: str | Path) -> Mapping[str, object]:
    import joblib

    artifact = joblib.load(path)
    if not isinstance(artifact, Mapping):
        raise ValueError("model artifact did not contain a mapping")
    if artifact.get("kind") not in {MODEL_KIND, LEGACY_MODEL_KIND}:
        raise ValueError(f"unsupported model kind: {artifact.get('kind')}")
    return artifact


def score_windows(
    windows: Iterable[EndpointWindow],
    model_artifact: Mapping[str, object],
    *,
    threshold: float | None = None,
    include_below_threshold: bool = False,
) -> list[MLAlert]:
    window_list = list(windows)
    model = model_artifact["model"]
    scorer = _artifact_scorer(model_artifact)
    model_id = str(model_artifact.get("model_id", "unknown-model"))
    alert_threshold = float(threshold if threshold is not None else model_artifact.get("threshold", 0.5))
    high_threshold = _as_optional_float(model_artifact.get("high_threshold"))
    alerts: list[MLAlert] = []
    scores = _score_many(window_list, model, scorer)
    for window, score in zip(window_list, scores):
        if score < alert_threshold and not include_below_threshold:
            continue
        alerts.append(
            _alert_for_window(
                window,
                model_id,
                score,
                alert_threshold,
                scorer=scorer,
                high_threshold=high_threshold,
            )
        )
    return sorted(alerts, key=lambda item: item.score, reverse=True)


def alerts_to_records(alerts: Iterable[MLAlert]) -> list[dict[str, object]]:
    return [alert_to_record(alert) for alert in alerts]


def alert_to_record(alert: MLAlert) -> dict[str, object]:
    return {
        "id": alert.id,
        "model_id": alert.model_id,
        "endpoint": alert.endpoint,
        "role": alert.role,
        "window_start": alert.window_start.isoformat(),
        "window_end": alert.window_end.isoformat(),
        "score": alert.score,
        "threshold": alert.threshold,
        "severity": alert.severity,
        "reasons": list(alert.reasons),
        "features": dict(alert.features),
        "created_at": alert.created_at.isoformat(),
    }


def write_alerts(alerts: Iterable[MLAlert], path: str | Path | None) -> str | None:
    records = alerts_to_records(alerts)
    payload = json.dumps(records, indent=2, sort_keys=True) + "\n"
    if path is None:
        return payload
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(payload, encoding="utf-8")
    return None


def metadata_record(result: ModelTrainingResult) -> dict[str, object]:
    metadata = json.loads(result.metadata_path.read_text(encoding="utf-8"))
    if not isinstance(metadata, dict):
        raise ValueError("metadata file did not contain a mapping")
    return metadata


def evaluate_temporal_split(
    windows: Iterable[EndpointWindow],
    *,
    train_fraction: float = 0.7,
    threshold_quantile: float = 0.95,
    seed: int = 42,
    min_year: int | None = 2000,
    feature_names: Iterable[str] | None = None,
) -> dict[str, object]:
    raw_windows = list(windows)
    excluded_windows = [
        window for window in raw_windows if min_year is not None and window.window_start.year < min_year
    ]
    window_list = sorted(
        [window for window in raw_windows if min_year is None or window.window_start.year >= min_year],
        key=lambda item: (item.window_start, item.window_end, item.endpoint, item.role, item.id),
    )
    if len(window_list) < 2:
        raise ValueError("cannot evaluate fewer than two endpoint windows")
    if not 0.0 < train_fraction < 1.0:
        raise ValueError("train_fraction must be in the range (0, 1)")
    if not 0.0 < threshold_quantile <= 1.0:
        raise ValueError("threshold_quantile must be in the range (0, 1]")

    import numpy as np
    from river import anomaly, compose, preprocessing
    from sklearn.ensemble import IsolationForest
    from sklearn.metrics import average_precision_score, precision_recall_curve, precision_recall_fscore_support, roc_auc_score
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import FunctionTransformer

    model_feature_names = _resolve_feature_names(feature_names)
    split_index = max(1, min(len(window_list) - 1, int(len(window_list) * train_fraction)))
    train_windows = window_list[:split_index]
    test_windows = window_list[split_index:]
    fit_windows = [window for window in train_windows if window.label != "malicious"] or train_windows
    test_labels = np.array([1 if window.label == "malicious" else 0 for window in test_windows], dtype=int)
    has_binary_test_labels = len(set(int(label) for label in test_labels)) == 2

    result: dict[str, object] = {
        "version": MODEL_VERSION,
        "seed": seed,
        "threshold_quantile": threshold_quantile,
        "data_quality": {
            "input_rows": len(raw_windows),
            "evaluated_rows": len(window_list),
            "excluded_rows": len(excluded_windows),
            "min_year": min_year,
        },
        "split": {
            "method": "temporal",
            "train_fraction": train_fraction,
            "split_index": split_index,
            "train_rows": len(train_windows),
            "fit_rows": len(fit_windows),
            "test_rows": len(test_windows),
            "train_start": train_windows[0].window_start.isoformat(),
            "train_end": train_windows[-1].window_end.isoformat(),
            "test_start": test_windows[0].window_start.isoformat(),
            "test_end": test_windows[-1].window_end.isoformat(),
        },
        "labels": {
            "train": _label_counts(train_windows),
            "fit": _label_counts(fit_windows),
            "test": _label_counts(test_windows),
        },
        "scorers": {},
    }
    scorers: dict[str, object] = {}

    river_model = compose.Pipeline(
        preprocessing.MinMaxScaler(),
        anomaly.HalfSpaceTrees(n_trees=25, height=8, window_size=max(16, min(250, len(fit_windows))), seed=seed),
    )
    for window in fit_windows:
        river_model.learn_one(feature_vector(window, model_feature_names))
    river_train_scores = np.array([float(river_model.score_one(feature_vector(window, model_feature_names))) for window in fit_windows], dtype=float)
    river_test_scores = np.array([float(river_model.score_one(feature_vector(window, model_feature_names))) for window in test_windows], dtype=float)
    river_threshold = max(float(np.quantile(river_train_scores, threshold_quantile)), 0.05)
    river_high_threshold = _high_threshold(river_train_scores, river_threshold)
    scorers[SCORER_RIVER] = _evaluation_metrics(
        river_test_scores,
        test_labels,
        test_windows,
        threshold=river_threshold,
        high_threshold=river_high_threshold,
        roc_auc_score=roc_auc_score if has_binary_test_labels else None,
        average_precision_score=average_precision_score if has_binary_test_labels else None,
        precision_recall_curve=precision_recall_curve if has_binary_test_labels else None,
        precision_recall_fscore_support=precision_recall_fscore_support if has_binary_test_labels else None,
    )

    fit_matrix = np.array([[feature_vector(window, model_feature_names)[name] for name in model_feature_names] for window in fit_windows], dtype=float)
    test_matrix = np.array([[feature_vector(window, model_feature_names)[name] for name in model_feature_names] for window in test_windows], dtype=float)
    if len(fit_windows) >= 2:
        raw_isolation = IsolationForest(random_state=seed, contamination="auto")
        raw_isolation.fit(fit_matrix)
        raw_train_scores = -raw_isolation.decision_function(fit_matrix)
        raw_test_scores = -raw_isolation.decision_function(test_matrix)
        raw_threshold = float(np.quantile(raw_train_scores, threshold_quantile))
        raw_high_threshold = _high_threshold(raw_train_scores, raw_threshold)
        scorers[SCORER_ISOLATION_RAW] = _evaluation_metrics(
            raw_test_scores,
            test_labels,
            test_windows,
            threshold=raw_threshold,
            high_threshold=raw_high_threshold,
            roc_auc_score=roc_auc_score if has_binary_test_labels else None,
            average_precision_score=average_precision_score if has_binary_test_labels else None,
            precision_recall_curve=precision_recall_curve if has_binary_test_labels else None,
            precision_recall_fscore_support=precision_recall_fscore_support if has_binary_test_labels else None,
        )

        isolation_log1p = make_pipeline(
            FunctionTransformer(np.log1p, validate=False),
            IsolationForest(random_state=seed, contamination="auto"),
        )
        isolation_log1p.fit(fit_matrix)
        log_train_scores = -isolation_log1p.decision_function(fit_matrix)
        log_test_scores = -isolation_log1p.decision_function(test_matrix)
        log_threshold = float(np.quantile(log_train_scores, threshold_quantile))
        log_high_threshold = _high_threshold(log_train_scores, log_threshold)
        scorers[SCORER_ISOLATION_LOG1P] = _evaluation_metrics(
            log_test_scores,
            test_labels,
            test_windows,
            threshold=log_threshold,
            high_threshold=log_high_threshold,
            roc_auc_score=roc_auc_score if has_binary_test_labels else None,
            average_precision_score=average_precision_score if has_binary_test_labels else None,
            precision_recall_curve=precision_recall_curve if has_binary_test_labels else None,
            precision_recall_fscore_support=precision_recall_fscore_support if has_binary_test_labels else None,
        )
    else:
        skipped = {"skipped": "fewer than two training rows"}
        scorers[SCORER_ISOLATION_RAW] = skipped
        scorers[SCORER_ISOLATION_LOG1P] = skipped

    result["scorers"] = scorers
    result["features"] = {
        "used": list(model_feature_names),
        "excluded": [name for name in FEATURE_NAMES if name not in set(model_feature_names)],
    }
    result["best_scorers"] = _best_evaluation_scorers(scorers)
    return result


def tune_temporal_split(
    windows: Iterable[EndpointWindow],
    *,
    train_fraction: float = 0.6,
    calibration_fraction: float = 0.2,
    threshold_quantile: float = 0.95,
    threshold_objective: str = THRESHOLD_OBJECTIVE_BEST_F1,
    target_fpr: float = DEFAULT_TARGET_FPR,
    target_alerts_per_day: float = DEFAULT_TARGET_ALERTS_PER_DAY,
    seed: int = 42,
    min_year: int | None = 2000,
) -> dict[str, object]:
    threshold_objective = _normalize_threshold_objective(threshold_objective)
    raw_windows = list(windows)
    excluded_windows = [
        window for window in raw_windows if min_year is not None and window.window_start.year < min_year
    ]
    window_list = sorted(
        [window for window in raw_windows if min_year is None or window.window_start.year >= min_year],
        key=lambda item: (item.window_start, item.window_end, item.endpoint, item.role, item.id),
    )
    if len(window_list) < 3:
        raise ValueError("cannot tune fewer than three endpoint windows")
    if not 0.0 < train_fraction < 1.0:
        raise ValueError("train_fraction must be in the range (0, 1)")
    if not 0.0 < calibration_fraction < 1.0:
        raise ValueError("calibration_fraction must be in the range (0, 1)")
    if train_fraction + calibration_fraction >= 1.0:
        raise ValueError("train_fraction plus calibration_fraction must be less than 1")
    if not 0.0 < threshold_quantile <= 1.0:
        raise ValueError("threshold_quantile must be in the range (0, 1]")
    if not 0.0 <= target_fpr <= 1.0:
        raise ValueError("target_fpr must be in the range [0, 1]")
    if target_alerts_per_day <= 0.0:
        raise ValueError("target_alerts_per_day must be greater than 0")

    import numpy as np
    from river import anomaly, compose, preprocessing
    from sklearn.ensemble import IsolationForest
    from sklearn.metrics import average_precision_score, precision_recall_curve, precision_recall_fscore_support, roc_auc_score
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import FunctionTransformer

    train_end = max(1, min(len(window_list) - 2, int(len(window_list) * train_fraction)))
    calibration_end = max(train_end + 1, min(len(window_list) - 1, int(len(window_list) * (train_fraction + calibration_fraction))))
    train_windows = window_list[:train_end]
    calibration_windows = window_list[train_end:calibration_end]
    test_windows = window_list[calibration_end:]
    fit_windows = [window for window in train_windows if window.label != "malicious"] or train_windows

    calibration_labels = np.array([1 if window.label == "malicious" else 0 for window in calibration_windows], dtype=int)
    test_labels = np.array([1 if window.label == "malicious" else 0 for window in test_windows], dtype=int)
    has_binary_calibration_labels = len(set(int(label) for label in calibration_labels)) == 2
    has_binary_test_labels = len(set(int(label) for label in test_labels)) == 2

    result: dict[str, object] = {
        "version": MODEL_VERSION,
        "seed": seed,
        "threshold_quantile": threshold_quantile,
        "threshold_objective": threshold_objective,
        "target_fpr": target_fpr,
        "target_alerts_per_day": target_alerts_per_day,
        "data_quality": {
            "input_rows": len(raw_windows),
            "evaluated_rows": len(window_list),
            "excluded_rows": len(excluded_windows),
            "min_year": min_year,
        },
        "split": {
            "method": "temporal_train_calibration_test",
            "train_fraction": train_fraction,
            "calibration_fraction": calibration_fraction,
            "train_rows": len(train_windows),
            "fit_rows": len(fit_windows),
            "calibration_rows": len(calibration_windows),
            "test_rows": len(test_windows),
            "train_start": train_windows[0].window_start.isoformat(),
            "train_end": train_windows[-1].window_end.isoformat(),
            "calibration_start": calibration_windows[0].window_start.isoformat(),
            "calibration_end": calibration_windows[-1].window_end.isoformat(),
            "test_start": test_windows[0].window_start.isoformat(),
            "test_end": test_windows[-1].window_end.isoformat(),
        },
        "labels": {
            "train": _label_counts(train_windows),
            "fit": _label_counts(fit_windows),
            "calibration": _label_counts(calibration_windows),
            "test": _label_counts(test_windows),
        },
        "scorers": {},
    }
    scorers: dict[str, object] = {}

    river_model = compose.Pipeline(
        preprocessing.MinMaxScaler(),
        anomaly.HalfSpaceTrees(n_trees=25, height=8, window_size=max(16, min(250, len(fit_windows))), seed=seed),
    )
    for window in fit_windows:
        river_model.learn_one(feature_vector(window))
    river_train_scores = np.array([float(river_model.score_one(feature_vector(window))) for window in fit_windows], dtype=float)
    river_calibration_scores = np.array([float(river_model.score_one(feature_vector(window))) for window in calibration_windows], dtype=float)
    river_test_scores = np.array([float(river_model.score_one(feature_vector(window))) for window in test_windows], dtype=float)
    scorers[SCORER_RIVER] = _tuned_scorer_metrics(
        river_train_scores,
        river_calibration_scores,
        river_test_scores,
        calibration_labels,
        test_labels,
        calibration_windows,
        test_windows,
        threshold_quantile=threshold_quantile,
        has_binary_calibration_labels=has_binary_calibration_labels,
        has_binary_test_labels=has_binary_test_labels,
        roc_auc_score=roc_auc_score,
        average_precision_score=average_precision_score,
        precision_recall_curve=precision_recall_curve,
        precision_recall_fscore_support=precision_recall_fscore_support,
        threshold_objective=threshold_objective,
        target_fpr=target_fpr,
        target_alerts_per_day=target_alerts_per_day,
    )

    fit_matrix = np.array([[feature_vector(window)[name] for name in FEATURE_NAMES] for window in fit_windows], dtype=float)
    calibration_matrix = np.array([[feature_vector(window)[name] for name in FEATURE_NAMES] for window in calibration_windows], dtype=float)
    test_matrix = np.array([[feature_vector(window)[name] for name in FEATURE_NAMES] for window in test_windows], dtype=float)
    if len(fit_windows) >= 2:
        raw_isolation = IsolationForest(random_state=seed, contamination="auto")
        raw_isolation.fit(fit_matrix)
        scorers[SCORER_ISOLATION_RAW] = _tuned_scorer_metrics(
            -raw_isolation.decision_function(fit_matrix),
            -raw_isolation.decision_function(calibration_matrix),
            -raw_isolation.decision_function(test_matrix),
            calibration_labels,
            test_labels,
            calibration_windows,
            test_windows,
            threshold_quantile=threshold_quantile,
            has_binary_calibration_labels=has_binary_calibration_labels,
            has_binary_test_labels=has_binary_test_labels,
            roc_auc_score=roc_auc_score,
            average_precision_score=average_precision_score,
            precision_recall_curve=precision_recall_curve,
            precision_recall_fscore_support=precision_recall_fscore_support,
            threshold_objective=threshold_objective,
            target_fpr=target_fpr,
            target_alerts_per_day=target_alerts_per_day,
        )

        isolation_log1p = make_pipeline(
            FunctionTransformer(np.log1p, validate=False),
            IsolationForest(random_state=seed, contamination="auto"),
        )
        isolation_log1p.fit(fit_matrix)
        scorers[SCORER_ISOLATION_LOG1P] = _tuned_scorer_metrics(
            -isolation_log1p.decision_function(fit_matrix),
            -isolation_log1p.decision_function(calibration_matrix),
            -isolation_log1p.decision_function(test_matrix),
            calibration_labels,
            test_labels,
            calibration_windows,
            test_windows,
            threshold_quantile=threshold_quantile,
            has_binary_calibration_labels=has_binary_calibration_labels,
            has_binary_test_labels=has_binary_test_labels,
            roc_auc_score=roc_auc_score,
            average_precision_score=average_precision_score,
            precision_recall_curve=precision_recall_curve,
            precision_recall_fscore_support=precision_recall_fscore_support,
            threshold_objective=threshold_objective,
            target_fpr=target_fpr,
            target_alerts_per_day=target_alerts_per_day,
        )
    else:
        skipped = {"skipped": "fewer than two training rows"}
        scorers[SCORER_ISOLATION_RAW] = skipped
        scorers[SCORER_ISOLATION_LOG1P] = skipped

    result["scorers"] = scorers
    result["best_scorers"] = _best_tuned_scorers(scorers, phase="test")
    return result


def _tuned_scorer_metrics(
    train_scores,
    calibration_scores,
    test_scores,
    calibration_labels,
    test_labels,
    calibration_windows: list[EndpointWindow],
    test_windows: list[EndpointWindow],
    *,
    threshold_quantile: float,
    has_binary_calibration_labels: bool,
    has_binary_test_labels: bool,
    roc_auc_score,
    average_precision_score,
    precision_recall_curve,
    precision_recall_fscore_support,
    threshold_objective: str,
    target_fpr: float,
    target_alerts_per_day: float,
) -> dict[str, object]:
    import numpy as np

    quantile_threshold = float(np.quantile(train_scores, threshold_quantile))
    calibration_choice = _select_calibration_threshold(
        calibration_scores,
        calibration_labels,
        calibration_windows,
        fallback_threshold=quantile_threshold,
        threshold_objective=threshold_objective,
        target_fpr=target_fpr,
        target_alerts_per_day=target_alerts_per_day,
        has_binary_calibration_labels=has_binary_calibration_labels,
        precision_recall_curve=precision_recall_curve,
    )
    selected_threshold = float(calibration_choice["selected_threshold"])
    threshold_source = str(calibration_choice["threshold_source"])
    high_threshold = _high_threshold(train_scores, selected_threshold)
    calibration_metrics = _evaluation_metrics(
        calibration_scores,
        calibration_labels,
        calibration_windows,
        threshold=selected_threshold,
        high_threshold=high_threshold,
        roc_auc_score=roc_auc_score if has_binary_calibration_labels else None,
        average_precision_score=average_precision_score if has_binary_calibration_labels else None,
        precision_recall_curve=precision_recall_curve if has_binary_calibration_labels else None,
        precision_recall_fscore_support=precision_recall_fscore_support if has_binary_calibration_labels else None,
    )
    test_metrics = _evaluation_metrics(
        test_scores,
        test_labels,
        test_windows,
        threshold=selected_threshold,
        high_threshold=high_threshold,
        roc_auc_score=roc_auc_score if has_binary_test_labels else None,
        average_precision_score=average_precision_score if has_binary_test_labels else None,
        precision_recall_curve=precision_recall_curve if has_binary_test_labels else None,
        precision_recall_fscore_support=precision_recall_fscore_support if has_binary_test_labels else None,
    )
    return {
        "selected_threshold": selected_threshold,
        "threshold_source": threshold_source,
        "training_quantile_threshold": quantile_threshold,
        "high_threshold": high_threshold,
        "threshold_objective": threshold_objective,
        "target_fpr": target_fpr,
        "target_alerts_per_day": target_alerts_per_day,
        "calibration_selection": calibration_choice,
        "calibration": calibration_metrics,
        "test": test_metrics,
    }


def _select_calibration_threshold(
    scores,
    labels,
    windows: list[EndpointWindow],
    *,
    fallback_threshold: float,
    threshold_objective: str,
    target_fpr: float,
    target_alerts_per_day: float,
    has_binary_calibration_labels: bool,
    precision_recall_curve,
) -> dict[str, object]:
    if threshold_objective == THRESHOLD_OBJECTIVE_BEST_F1:
        if has_binary_calibration_labels:
            best_f1 = _best_f1_metrics(scores, labels, precision_recall_curve)
            best_threshold = best_f1.get("best_f1_threshold")
            if best_threshold is not None:
                return {
                    "objective": threshold_objective,
                    "selected_threshold": float(best_threshold),
                    "threshold_source": "calibration_best_f1",
                    "fallback_threshold": fallback_threshold,
                    **best_f1,
                }
            return _fallback_threshold_selection(
                fallback_threshold,
                threshold_objective,
                reason="calibration best-F1 threshold was unavailable",
            )
        return _fallback_threshold_selection(
            fallback_threshold,
            threshold_objective,
            reason="calibration labels were not binary",
        )

    candidates = _threshold_candidates(scores, labels, windows)
    if threshold_objective == THRESHOLD_OBJECTIVE_TARGET_FPR:
        if not has_binary_calibration_labels:
            return _fallback_threshold_selection(
                fallback_threshold,
                threshold_objective,
                reason="target-fpr requires binary calibration labels",
            )
        if not any(candidate.get("false_positive_rate") is not None for candidate in candidates):
            return _fallback_threshold_selection(
                fallback_threshold,
                threshold_objective,
                reason="target-fpr requires benign calibration windows",
            )
        valid = [
            candidate
            for candidate in candidates
            if candidate.get("false_positive_rate") is not None
            and float(candidate["false_positive_rate"]) <= target_fpr
        ]
        if not valid:
            return _fallback_threshold_selection(
                fallback_threshold,
                threshold_objective,
                reason="no threshold satisfied the target false-positive rate",
            )
        selected = max(
            valid,
            key=lambda candidate: (
                _metric_or_zero(candidate.get("recall_at_threshold")),
                _metric_or_zero(candidate.get("f1_at_threshold")),
                _metric_or_zero(candidate.get("precision_at_threshold")),
                -_metric_or_zero(candidate.get("false_positive_rate")),
                int(candidate.get("alerts", 0)),
            ),
        )
        return {
            "objective": threshold_objective,
            "selected_threshold": selected["threshold"],
            "threshold_source": "calibration_target_fpr",
            "fallback_threshold": fallback_threshold,
            "target_fpr": target_fpr,
            **selected,
        }

    if threshold_objective == THRESHOLD_OBJECTIVE_TARGET_ALERTS_PER_DAY:
        valid = [
            candidate
            for candidate in candidates
            if candidate.get("alerts_per_day") is not None
            and float(candidate["alerts_per_day"]) <= target_alerts_per_day
        ]
        if not valid:
            return _fallback_threshold_selection(
                fallback_threshold,
                threshold_objective,
                reason="calibration duration did not support an alerts/day budget",
            )
        selected = max(
            valid,
            key=lambda candidate: (
                _metric_or_zero(candidate.get("recall_at_threshold")),
                int(candidate.get("alerts", 0)),
                _metric_or_zero(candidate.get("f1_at_threshold")),
                _metric_or_zero(candidate.get("precision_at_threshold")),
            ),
        )
        return {
            "objective": threshold_objective,
            "selected_threshold": selected["threshold"],
            "threshold_source": "calibration_target_alerts_per_day",
            "fallback_threshold": fallback_threshold,
            "target_alerts_per_day": target_alerts_per_day,
            **selected,
        }

    raise ValueError(f"unsupported threshold objective: {threshold_objective}")


def _fallback_threshold_selection(fallback_threshold: float, objective: str, *, reason: str) -> dict[str, object]:
    return {
        "objective": objective,
        "selected_threshold": fallback_threshold,
        "threshold_source": "training_quantile",
        "fallback_threshold": fallback_threshold,
        "reason": reason,
        "best_f1": None,
        "best_f1_threshold": None,
        "best_f1_precision": None,
        "best_f1_recall": None,
        "best_f1_alerts": None,
    }


def _threshold_candidates(scores, labels, windows: list[EndpointWindow]) -> list[dict[str, object]]:
    import numpy as np

    if len(scores) == 0:
        return []

    scores_array = np.asarray(scores, dtype=float)
    labels_array = np.asarray(labels, dtype=int)
    order = np.argsort(scores_array)[::-1]
    sorted_scores = scores_array[order]
    sorted_labels = labels_array[order]
    positive_total = int(np.sum(labels_array == 1))
    negative_total = int(np.sum(labels_array == 0))
    duration_days = _duration_days(windows)
    candidates: list[dict[str, object]] = [
        _candidate_record(
            threshold=float(np.nextafter(np.max(scores_array), np.inf)),
            alerts=0,
            true_positives=0,
            false_positives=0,
            positive_total=positive_total,
            negative_total=negative_total,
            duration_days=duration_days,
        )
    ]

    alerts = 0
    true_positives = 0
    false_positives = 0
    index = 0
    while index < len(sorted_scores):
        score = float(sorted_scores[index])
        end = index + 1
        while end < len(sorted_scores) and sorted_scores[end] == sorted_scores[index]:
            end += 1
        group_labels = sorted_labels[index:end]
        alerts = end
        true_positives += int(np.sum(group_labels == 1))
        false_positives += int(np.sum(group_labels == 0))
        candidates.append(
            _candidate_record(
                threshold=score,
                alerts=alerts,
                true_positives=true_positives,
                false_positives=false_positives,
                positive_total=positive_total,
                negative_total=negative_total,
                duration_days=duration_days,
            )
        )
        index = end
    return candidates


def _candidate_record(
    *,
    threshold: float,
    alerts: int,
    true_positives: int,
    false_positives: int,
    positive_total: int,
    negative_total: int,
    duration_days: float | None,
) -> dict[str, object]:
    precision = _safe_div(true_positives, alerts)
    recall = _safe_div(true_positives, positive_total)
    false_positive_rate = _safe_div(false_positives, negative_total)
    false_negatives = positive_total - true_positives
    true_negatives = negative_total - false_positives
    f1 = None
    if precision is not None and recall is not None and precision + recall > 0:
        f1 = float((2 * precision * recall) / (precision + recall))
    return {
        "threshold": float(threshold),
        "alerts": alerts,
        "alerts_per_day": None if duration_days is None else float(alerts / duration_days),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "true_negatives": true_negatives,
        "false_negatives": false_negatives,
        "false_positive_rate": false_positive_rate,
        "true_positive_rate": recall,
        "precision_at_threshold": precision,
        "recall_at_threshold": recall,
        "f1_at_threshold": f1,
    }


def _evaluation_metrics(
    scores,
    labels,
    windows: list[EndpointWindow],
    *,
    threshold: float,
    high_threshold: float,
    roc_auc_score,
    average_precision_score,
    precision_recall_curve,
    precision_recall_fscore_support,
) -> dict[str, object]:
    import numpy as np

    predictions = scores >= threshold
    high_predictions = scores >= high_threshold
    alerts = int(np.sum(predictions))
    high_alerts = int(np.sum(high_predictions))
    medium_alerts = int(alerts - high_alerts)
    positives = labels == 1
    negatives = labels == 0
    true_positives = int(np.sum(predictions & positives))
    false_positives = int(np.sum(predictions & negatives))
    true_negatives = int(np.sum(~predictions & negatives))
    false_negatives = int(np.sum(~predictions & positives))
    metrics: dict[str, object] = {
        "threshold": float(threshold),
        "high_threshold": float(high_threshold),
        "score_min": float(np.min(scores)),
        "score_max": float(np.max(scores)),
        "score_mean": float(np.mean(scores)),
        "alerts": alerts,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "alert_rate": _safe_div(alerts, len(windows)),
        "alerts_per_day": _alerts_per_day(alerts, windows),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "true_negatives": true_negatives,
        "false_negatives": false_negatives,
        "false_positive_rate": _safe_div(false_positives, int(np.sum(negatives))),
        "true_positive_rate": _safe_div(true_positives, int(np.sum(positives))),
    }
    if (
        roc_auc_score is None
        or average_precision_score is None
        or precision_recall_curve is None
        or precision_recall_fscore_support is None
    ):
        metrics["roc_auc"] = None
        metrics["pr_auc"] = None
        metrics["precision_at_threshold"] = None
        metrics["recall_at_threshold"] = None
        metrics["f1_at_threshold"] = None
        metrics["best_f1"] = None
        metrics["best_f1_threshold"] = None
        metrics["best_f1_precision"] = None
        metrics["best_f1_recall"] = None
        metrics["best_f1_alerts"] = None
        return metrics

    precision, recall, f1, _ = precision_recall_fscore_support(
        labels,
        predictions,
        average="binary",
        zero_division=0,
    )
    metrics["roc_auc"] = float(roc_auc_score(labels, scores))
    metrics["pr_auc"] = float(average_precision_score(labels, scores))
    metrics["precision_at_threshold"] = float(precision)
    metrics["recall_at_threshold"] = float(recall)
    metrics["f1_at_threshold"] = float(f1)
    metrics.update(_best_f1_metrics(scores, labels, precision_recall_curve))
    return metrics


def _best_f1_metrics(scores, labels, precision_recall_curve) -> dict[str, object]:
    import numpy as np

    precision, recall, thresholds = precision_recall_curve(labels, scores)
    if len(thresholds) == 0:
        return {
            "best_f1": None,
            "best_f1_threshold": None,
            "best_f1_precision": None,
            "best_f1_recall": None,
            "best_f1_alerts": None,
        }
    threshold_precision = precision[:-1]
    threshold_recall = recall[:-1]
    denominator = threshold_precision + threshold_recall
    f1_scores = np.divide(
        2 * threshold_precision * threshold_recall,
        denominator,
        out=np.zeros_like(denominator),
        where=denominator > 0,
    )
    best_index = int(np.argmax(f1_scores))
    best_threshold = float(thresholds[best_index])
    return {
        "best_f1": float(f1_scores[best_index]),
        "best_f1_threshold": best_threshold,
        "best_f1_precision": float(threshold_precision[best_index]),
        "best_f1_recall": float(threshold_recall[best_index]),
        "best_f1_alerts": int(np.sum(scores >= best_threshold)),
    }


def _label_counts(windows: Iterable[EndpointWindow]) -> dict[str, int]:
    counts = {"benign": 0, "malicious": 0, "unknown": 0}
    for window in windows:
        label = window.label if window.label in counts else "unknown"
        counts[label] += 1
    return counts


def _best_evaluation_scorers(scorers: Mapping[str, object]) -> dict[str, str | None]:
    best: dict[str, str | None] = {}
    for metric in ("pr_auc", "roc_auc", "f1_at_threshold", "best_f1", "precision_at_threshold", "recall_at_threshold"):
        ranked: list[tuple[float, str]] = []
        for scorer, raw_metrics in scorers.items():
            if not isinstance(raw_metrics, Mapping):
                continue
            value = raw_metrics.get(metric)
            if isinstance(value, (float, int)):
                ranked.append((float(value), scorer))
        best[metric] = max(ranked)[1] if ranked else None
    for metric in ("false_positive_rate", "alerts_per_day"):
        ranked = []
        for scorer, raw_metrics in scorers.items():
            if not isinstance(raw_metrics, Mapping):
                continue
            value = raw_metrics.get(metric)
            if isinstance(value, (float, int)):
                ranked.append((float(value), scorer))
        best[f"lowest_{metric}"] = min(ranked)[1] if ranked else None
    return best


def _best_tuned_scorers(scorers: Mapping[str, object], *, phase: str) -> dict[str, str | None]:
    best: dict[str, str | None] = {}
    for metric in ("pr_auc", "roc_auc", "f1_at_threshold", "best_f1", "precision_at_threshold", "recall_at_threshold"):
        ranked: list[tuple[float, str]] = []
        for scorer, raw_metrics in scorers.items():
            if not isinstance(raw_metrics, Mapping):
                continue
            phase_metrics = raw_metrics.get(phase)
            if not isinstance(phase_metrics, Mapping):
                continue
            value = phase_metrics.get(metric)
            if isinstance(value, (float, int)):
                ranked.append((float(value), scorer))
        best[metric] = max(ranked)[1] if ranked else None
    for metric in ("false_positive_rate", "alerts_per_day"):
        ranked = []
        for scorer, raw_metrics in scorers.items():
            if not isinstance(raw_metrics, Mapping):
                continue
            phase_metrics = raw_metrics.get(phase)
            if not isinstance(phase_metrics, Mapping):
                continue
            value = phase_metrics.get(metric)
            if isinstance(value, (float, int)):
                ranked.append((float(value), scorer))
        best[f"lowest_{metric}"] = min(ranked)[1] if ranked else None
    return best


def _alerts_per_day(alerts: int, windows: list[EndpointWindow]) -> float | None:
    duration_days = _duration_days(windows)
    if duration_days is None:
        return None
    return float(alerts / duration_days)


def _duration_days(windows: list[EndpointWindow]) -> float | None:
    if not windows:
        return None
    start = min(window.window_start for window in windows)
    end = max(window.window_end for window in windows)
    seconds = (end - start).total_seconds()
    if seconds <= 0:
        return None
    return float(seconds / 86_400)


def _metric_or_zero(value: object) -> float:
    if isinstance(value, (float, int)):
        return float(value)
    return 0.0


def _safe_div(numerator: int | float, denominator: int | float) -> float | None:
    if denominator == 0:
        return None
    return float(numerator / denominator)


def _add_score_metrics(
    metrics: dict[str, float | int | str],
    prefix: str,
    scores,
    labels,
    *,
    threshold: float,
    high_threshold: float,
    roc_auc_score,
    precision_recall_fscore_support,
) -> None:
    import numpy as np

    metrics[f"{prefix}_score_min"] = float(np.min(scores))
    metrics[f"{prefix}_score_max"] = float(np.max(scores))
    metrics[f"{prefix}_score_mean"] = float(np.mean(scores))
    metrics[f"{prefix}_threshold"] = float(threshold)
    metrics[f"{prefix}_high_threshold"] = float(high_threshold)
    if roc_auc_score is None or precision_recall_fscore_support is None:
        return
    metrics[f"{prefix}_roc_auc"] = float(roc_auc_score(labels, scores))
    predictions = scores >= threshold
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels,
        predictions,
        average="binary",
        zero_division=0,
    )
    metrics[f"{prefix}_alerts_at_threshold"] = int(np.sum(predictions))
    metrics[f"{prefix}_precision_at_threshold"] = float(precision)
    metrics[f"{prefix}_recall_at_threshold"] = float(recall)
    metrics[f"{prefix}_f1_at_threshold"] = float(f1)


def _select_scorer(
    requested_scorer: str,
    candidate_models: Mapping[str, object],
    metrics: Mapping[str, float | int | str],
) -> str:
    if requested_scorer != SCORER_AUTO:
        if requested_scorer not in candidate_models:
            raise ValueError(f"{requested_scorer} requires at least two training rows")
        return requested_scorer

    ranked: list[tuple[float, int, str]] = []
    preferences = {
        SCORER_ISOLATION_LOG1P: 2,
        SCORER_RIVER: 1,
    }
    for scorer_name in candidate_models:
        metric_name = f"{_metric_prefix(scorer_name)}_roc_auc"
        metric = metrics.get(metric_name)
        if isinstance(metric, (float, int)):
            ranked.append((float(metric), preferences.get(scorer_name, 0), scorer_name))
    if ranked:
        river_auc = next((auc for auc, _preference, scorer in ranked if scorer == SCORER_RIVER), None)
        best_auc = max(auc for auc, _preference, _scorer in ranked)
        if river_auc is not None and best_auc <= river_auc + AUTO_SELECTION_AUC_MARGIN:
            return SCORER_RIVER
        return max(ranked)[2]
    if SCORER_ISOLATION_LOG1P in candidate_models:
        return SCORER_ISOLATION_LOG1P
    return SCORER_RIVER


def _high_threshold(train_scores, threshold: float) -> float:
    import numpy as np

    high_threshold = float(np.quantile(train_scores, HIGH_SEVERITY_QUANTILE))
    if high_threshold <= threshold:
        high_threshold = threshold + max(abs(threshold) * 0.5, 0.05)
    return high_threshold


def _normalize_scorer(scorer: str) -> str:
    aliases = {
        SCORER_AUTO: SCORER_AUTO,
        "river": SCORER_RIVER,
        SCORER_RIVER: SCORER_RIVER,
        "isolation": SCORER_ISOLATION_LOG1P,
        "isolation-forest": SCORER_ISOLATION_LOG1P,
        SCORER_ISOLATION_LOG1P: SCORER_ISOLATION_LOG1P,
    }
    normalized = aliases.get(scorer)
    if normalized is None:
        supported = ", ".join(SUPPORTED_SCORERS)
        raise ValueError(f"unsupported scorer: {scorer}; choose one of {supported}")
    return normalized


def _normalize_threshold_objective(objective: str) -> str:
    normalized = objective.strip().lower()
    aliases = {
        THRESHOLD_OBJECTIVE_BEST_F1: THRESHOLD_OBJECTIVE_BEST_F1,
        "f1": THRESHOLD_OBJECTIVE_BEST_F1,
        "best_f1": THRESHOLD_OBJECTIVE_BEST_F1,
        THRESHOLD_OBJECTIVE_TARGET_FPR: THRESHOLD_OBJECTIVE_TARGET_FPR,
        "target_fpr": THRESHOLD_OBJECTIVE_TARGET_FPR,
        "fpr": THRESHOLD_OBJECTIVE_TARGET_FPR,
        THRESHOLD_OBJECTIVE_TARGET_ALERTS_PER_DAY: THRESHOLD_OBJECTIVE_TARGET_ALERTS_PER_DAY,
        "target_alerts_per_day": THRESHOLD_OBJECTIVE_TARGET_ALERTS_PER_DAY,
        "alerts-per-day": THRESHOLD_OBJECTIVE_TARGET_ALERTS_PER_DAY,
        "alerts_per_day": THRESHOLD_OBJECTIVE_TARGET_ALERTS_PER_DAY,
    }
    selected = aliases.get(normalized)
    if selected is None:
        supported = ", ".join(SUPPORTED_THRESHOLD_OBJECTIVES)
        raise ValueError(f"unsupported threshold objective: {objective}; choose one of {supported}")
    return selected


def _metric_prefix(scorer: str) -> str:
    if scorer == SCORER_RIVER:
        return "river"
    if scorer == SCORER_ISOLATION_LOG1P:
        return "isolation_log1p"
    return scorer.replace("-", "_")


def _artifact_scorer(model_artifact: Mapping[str, object]) -> str:
    scorer = model_artifact.get("selected_scorer")
    if isinstance(scorer, str):
        return _normalize_scorer(scorer)
    if model_artifact.get("kind") == LEGACY_MODEL_KIND:
        return SCORER_RIVER
    model = model_artifact.get("model")
    if hasattr(model, "decision_function"):
        return SCORER_ISOLATION_LOG1P
    return SCORER_RIVER


def _score_many(windows: list[EndpointWindow], model: object, scorer: str) -> list[float]:
    if not windows:
        return []
    if scorer == SCORER_ISOLATION_LOG1P:
        import numpy as np

        matrix = np.array([[feature_vector(window)[name] for name in FEATURE_NAMES] for window in windows], dtype=float)
        return [float(score) for score in -model.decision_function(matrix)]  # type: ignore[attr-defined]
    return [float(model.score_one(feature_vector(window))) for window in windows]  # type: ignore[attr-defined]


def _as_optional_float(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _alert_for_window(
    window: EndpointWindow,
    model_id: str,
    score: float,
    threshold: float,
    *,
    scorer: str,
    high_threshold: float | None,
) -> MLAlert:
    features = feature_vector(window)
    relation = "crossed" if score >= threshold else "below"
    reasons = [f"{scorer} anomaly score {score:.4f} {relation} threshold {threshold:.4f}"]
    for name, value in _top_features(features):
        reasons.append(f"{name.replace('_', ' ')}={value:g}")
    return MLAlert(
        id=_alert_id(model_id, window, score),
        model_id=model_id,
        endpoint=window.endpoint,
        role=window.role,
        window_start=window.window_start,
        window_end=window.window_end,
        score=round(score, 6),
        threshold=round(threshold, 6),
        severity=_severity(score, threshold, high_threshold),
        reasons=tuple(reasons),
        features=features,
        created_at=_now(),
    )


def _top_features(features: Mapping[str, float]) -> list[tuple[str, float]]:
    nonzero = [(name, float(value)) for name, value in features.items() if float(value) > 0]
    return sorted(nonzero, key=lambda item: item[1], reverse=True)[:5]


def _severity(score: float, threshold: float, high_threshold: float | None = None) -> str:
    if high_threshold is None:
        high_threshold = max(threshold * 2.0, threshold + 0.5)
    if score >= high_threshold:
        return "high"
    if score >= threshold:
        return "medium"
    return "low"


def _model_id(windows: list[EndpointWindow], seed: int) -> str:
    digest = hashlib.sha1()
    digest.update(MODEL_VERSION.encode("utf-8"))
    digest.update(str(seed).encode("utf-8"))
    for window in windows[:5000]:
        digest.update(json.dumps(window_to_record(window), sort_keys=True).encode("utf-8"))
    return digest.hexdigest()[:20]


def _alert_id(model_id: str, window: EndpointWindow, score: float) -> str:
    raw = f"{model_id}|{window.id}|{score:.8f}".encode("utf-8")
    return hashlib.sha1(raw).hexdigest()[:20]


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)
