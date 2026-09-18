"""
Preprocessing pipeline for NIDS data.
Fitted on training data → saved alongside model → reused during prediction.
Prevents data leakage by design.
"""
import os
import json
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from backend.ml.feature_config import (
    FEATURE_NAMES, map_columns, find_label_column, DROP_COLUMNS
)
from backend.ml.attack_taxonomy import normalize_labels_series
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class NIDSPreprocessor:
    """
    Stateful preprocessing pipeline.
    Call fit_transform() on training data.
    Call transform() on new data (prediction/test).
    """

    def __init__(self):
        self.imputer = SimpleImputer(strategy="median")
        self.scaler = StandardScaler()
        self.feature_names: list = []
        self.is_fitted: bool = False

    def fit_transform(self, df: pd.DataFrame) -> tuple:
        """
        Full training preprocessing.
        Returns (X_array, y_series, feature_names_used)
        """
        df = self._clean(df)
        label_col = find_label_column(list(df.columns))
        if not label_col:
            raise ValueError("No label column found. Expected one of: Label, Class, Attack.")

        # Normalize labels
        y = normalize_labels_series(df[label_col])
        X = df.drop(columns=[label_col])

        # Drop metadata columns that are not features
        X = self._drop_metadata(X)

        # Rename to canonical feature names
        rename_map = map_columns(list(X.columns))
        X = X.rename(columns=rename_map)

        # Keep only known feature columns
        available = [f for f in FEATURE_NAMES if f in X.columns]
        if len(available) < 10:
            raise ValueError(
                f"Too few recognizable feature columns: {len(available)}. "
                f"Dataset may be incompatible."
            )
        X = X[available]
        self.feature_names = available

        logger.info(f"Using {len(self.feature_names)} features for training.")

        # Convert to numeric, coerce errors to NaN
        X = X.apply(pd.to_numeric, errors="coerce")

        # Impute then scale
        X_imputed = self.imputer.fit_transform(X)
        X_scaled = self.scaler.fit_transform(X_imputed)
        self.is_fitted = True

        return X_scaled, y, self.feature_names

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """
        Transform new data using the fitted pipeline.
        Raises if not fitted.
        """
        if not self.is_fitted:
            raise RuntimeError("Preprocessor is not fitted. Load from disk first.")

        # Clean
        df = self._clean(df)

        # Rename columns
        rename_map = map_columns(list(df.columns))
        df = df.rename(columns=rename_map)

        # Drop label column if accidentally present
        label_col = find_label_column(list(df.columns))
        if label_col:
            df = df.drop(columns=[label_col])

        # Align to training feature set
        for feat in self.feature_names:
            if feat not in df.columns:
                df[feat] = 0.0  # Fill missing features with 0
        df = df[self.feature_names]

        df = df.apply(pd.to_numeric, errors="coerce")
        X_imputed = self.imputer.transform(df)
        X_scaled = self.scaler.transform(X_imputed)
        return X_scaled

    def save(self, model_dir: str) -> None:
        """Save preprocessor artifacts to model directory."""
        os.makedirs(model_dir, exist_ok=True)
        joblib.dump(self.imputer, os.path.join(model_dir, "imputer.pkl"))
        joblib.dump(self.scaler, os.path.join(model_dir, "scaler.pkl"))
        feature_config = {"feature_names": self.feature_names, "is_fitted": self.is_fitted}
        with open(os.path.join(model_dir, "feature_config.json"), "w") as f:
            json.dump(feature_config, f, indent=2)
        logger.info(f"Preprocessor saved to {model_dir}")

    @classmethod
    def load(cls, model_dir: str) -> "NIDSPreprocessor":
        """Load a fitted preprocessor from disk."""
        pp = cls()
        pp.imputer = joblib.load(os.path.join(model_dir, "imputer.pkl"))
        pp.scaler = joblib.load(os.path.join(model_dir, "scaler.pkl"))
        with open(os.path.join(model_dir, "feature_config.json")) as f:
            fc = json.load(f)
        pp.feature_names = fc["feature_names"]
        pp.is_fitted = fc.get("is_fitted", True)
        logger.info(f"Preprocessor loaded from {model_dir} ({len(pp.feature_names)} features)")
        return pp

    @staticmethod
    def _clean(df: pd.DataFrame) -> pd.DataFrame:
        """Basic cleaning: strip column names, remove inf values, duplicates."""
        df = df.copy()
        df.columns = [str(c).strip() for c in df.columns]
        # Replace inf with NaN
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        return df

    @staticmethod
    def _drop_metadata(df: pd.DataFrame) -> pd.DataFrame:
        """Drop metadata columns that should not be used as features."""
        to_drop = [c for c in df.columns if c.strip() in DROP_COLUMNS]
        if to_drop:
            df = df.drop(columns=to_drop)
        return df
