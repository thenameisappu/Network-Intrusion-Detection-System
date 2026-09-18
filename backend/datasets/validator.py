"""
Dataset validator — validates uploaded CSV files before they enter the ML pipeline.
Rejects malformed datasets with clear error messages.
"""
import pandas as pd
import numpy as np
from backend.ml.feature_config import map_columns, find_label_column, FEATURE_NAMES
from backend.ml.attack_taxonomy import normalize_label
from backend.utils.logger import get_logger

logger = get_logger(__name__)

MIN_ROWS = 100
MIN_FEATURE_COLUMNS = 10


def validate_dataset(filepath: str) -> dict:
    """
    Validate a CSV dataset file.
    Returns a validation result dict with errors, warnings, and stats.
    """
    errors = []
    warnings = []
    stats = {}

    try:
        # Try reading with different encodings
        try:
            df = pd.read_csv(filepath, low_memory=False)
        except UnicodeDecodeError:
            df = pd.read_csv(filepath, encoding="latin-1", low_memory=False)
        except Exception as e:
            return {"valid": False, "errors": [f"Cannot read CSV: {str(e)}"], "warnings": []}

        # Strip column whitespace
        df.columns = [str(c).strip() for c in df.columns]

        rows, cols = df.shape
        stats["total_rows"] = rows
        stats["total_columns"] = cols

        # Minimum rows check
        if rows < MIN_ROWS:
            errors.append(f"Dataset has only {rows} rows. Minimum {MIN_ROWS} required.")

        # Label column check
        label_col = find_label_column(list(df.columns))
        if not label_col:
            errors.append(
                "No label column found. Expected one of: Label, Class, Attack, Category."
            )
        else:
            stats["label_column"] = label_col
            label_counts = df[label_col].value_counts().to_dict()
            stats["label_distribution"] = {str(k): int(v) for k, v in label_counts.items()}

            # Check for unknown labels
            unknown_labels = []
            for lbl in label_counts:
                _, known = normalize_label(str(lbl))
                if not known:
                    unknown_labels.append(str(lbl))
            if unknown_labels:
                warnings.append(f"Unknown labels (will be mapped to 'Unknown'): {unknown_labels}")

        # Feature column check
        rename_map = map_columns(list(df.columns))
        recognized = list(rename_map.values())
        stats["recognized_features"] = len(recognized)
        stats["total_features"] = cols - (1 if label_col else 0)

        if len(recognized) < MIN_FEATURE_COLUMNS:
            errors.append(
                f"Only {len(recognized)} recognized feature columns found. "
                f"Minimum {MIN_FEATURE_COLUMNS} required. Dataset may be incompatible."
            )

        # Missing values
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        missing = df.isnull().sum()
        total_missing = int(missing.sum())
        stats["missing_values"] = total_missing
        stats["missing_rate"] = round(total_missing / (rows * cols) * 100, 2) if rows * cols > 0 else 0

        if stats["missing_rate"] > 30:
            warnings.append(f"High missing value rate: {stats['missing_rate']}%")

        # Duplicates
        dup_count = int(df.duplicated().sum())
        stats["duplicate_rows"] = dup_count
        if dup_count > rows * 0.5:
            warnings.append(f"High duplicate rate: {dup_count}/{rows} rows are duplicates.")

        # Data types
        numeric_cols = int(df.select_dtypes(include=[np.number]).shape[1])
        stats["numeric_columns"] = numeric_cols
        stats["non_numeric_columns"] = cols - numeric_cols

        # Sample preview (first 5 rows)
        stats["preview"] = df.head(5).fillna("").astype(str).to_dict(orient="records")
        stats["columns"] = list(df.columns)

        valid = len(errors) == 0
        logger.info(
            f"Dataset validation: valid={valid}, rows={rows}, features={len(recognized)}, "
            f"errors={len(errors)}, warnings={len(warnings)}"
        )

        return {
            "valid": valid,
            "errors": errors,
            "warnings": warnings,
            "stats": stats,
        }

    except Exception as e:
        logger.error(f"Validation exception: {e}")
        return {"valid": False, "errors": [f"Validation failed: {str(e)}"], "warnings": []}
