"""
Model evaluation — computes all required metrics from actual model predictions.
No fabricated values.
"""
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
)
from backend.utils.logger import get_logger

logger = get_logger(__name__)


def evaluate_model(model, X_test: np.ndarray, y_test, classes: list = None) -> dict:
    """
    Evaluate a trained sklearn model.
    Returns a metrics dictionary with all required performance indicators.
    """
    y_pred = model.predict(X_test)

    # Probabilities for AUC (if supported)
    roc_auc = None
    try:
        if hasattr(model, "predict_proba"):
            y_prob = model.predict_proba(X_test)
            if y_prob.shape[1] == 2:
                roc_auc = float(roc_auc_score(y_test, y_prob[:, 1]))
            else:
                # Multi-class OVR AUC
                roc_auc = float(
                    roc_auc_score(y_test, y_prob, multi_class="ovr", average="macro")
                )
    except Exception as e:
        logger.warning(f"Could not compute ROC-AUC: {e}")

    accuracy = float(accuracy_score(y_test, y_pred))
    precision_macro = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
    recall_macro = float(recall_score(y_test, y_pred, average="macro", zero_division=0))
    f1_macro = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
    f1_weighted = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
    precision_weighted = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
    recall_weighted = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))

    # Confusion matrix
    unique_labels = sorted(list(set(y_test) | set(y_pred)))
    cm = confusion_matrix(y_test, y_pred, labels=unique_labels)
    cm_list = cm.tolist()

    # Per-class classification report
    report = classification_report(
        y_test, y_pred, labels=unique_labels, zero_division=0, output_dict=True
    )

    metrics = {
        "accuracy": accuracy,
        "precision_macro": precision_macro,
        "recall_macro": recall_macro,
        "f1_macro": f1_macro,
        "f1_weighted": f1_weighted,
        "precision_weighted": precision_weighted,
        "recall_weighted": recall_weighted,
        "roc_auc": roc_auc,
        "confusion_matrix": cm_list,
        "confusion_matrix_labels": unique_labels,
        "classification_report": report,
        "test_samples": int(len(y_test)),
    }

    logger.info(
        f"Evaluation — Accuracy: {accuracy:.4f}, F1-macro: {f1_macro:.4f}, "
        f"F1-weighted: {f1_weighted:.4f}"
    )
    return metrics


def get_feature_importance(model, feature_names: list) -> list:
    """
    Extract feature importance for compatible models (Random Forest, Decision Tree).
    Returns sorted list of {feature, importance}.
    """
    importances = None
    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
    elif hasattr(model, "coef_"):
        # Logistic Regression — use mean absolute coefficient
        importances = np.abs(model.coef_).mean(axis=0)

    if importances is None:
        return []

    pairs = sorted(
        zip(feature_names, importances.tolist()),
        key=lambda x: x[1],
        reverse=True,
    )
    return [{"feature": f, "importance": round(i, 6)} for f, i in pairs]
