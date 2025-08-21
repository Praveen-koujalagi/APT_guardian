"""Data loading & preprocessing stubs.

Will include:
- load_dataset(path)
- extract_features(df)
- train_test_split

"""
from __future__ import annotations
from typing import Tuple, List, Dict, Any
import re
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, MinMaxScaler
import numpy as np

# Optional SMOTE
try:
    from imblearn.over_sampling import SMOTE  # type: ignore
    _HAS_SMOTE = True
except Exception:  # pragma: no cover
    _HAS_SMOTE = False


REQUIRED_COLUMNS: List[str] = [
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "packet_count", "byte_count"
]

# Columns / regex patterns to drop if found (identifiers / timestamps / non-predictive tokens)
DROP_PATTERNS = [
    r"mac", r"time", r"timestamp", r"flow_id", r"fwd_?header", r"bwd_?header", r"ip$", r"^src_ip$", r"^dst_ip$",
]
EXACT_DROP = {
    'src_ip','dst_ip','source_ip','destination_ip','timestamp','flow_id','flow_id','src_mac','dst_mac','frame.time'
}


def load_dataset(path: str) -> pd.DataFrame:
    """Load CSV dataset safely returning empty frame if missing."""
    try:
        df = pd.read_csv(path)
    except FileNotFoundError:
        return pd.DataFrame(columns=REQUIRED_COLUMNS + ["label"])  # include label placeholder
    return df


def basic_clean(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    df = df.copy()
    df = df.drop_duplicates()
    num_cols = list(df.select_dtypes(include=["number"]).columns)
    obj_cols = list(df.select_dtypes(include=["object"]).columns)
    if num_cols:
        df[num_cols] = df[num_cols].fillna(0)
    if obj_cols:
        df[obj_cols] = df[obj_cols].fillna("UNKNOWN")
    return df


def encode_and_scale(df: pd.DataFrame, scaler_type: str = "standard") -> Tuple[pd.DataFrame, Any]:
    if df.empty:
        return df, StandardScaler()
    work = df.copy()
    # Simple protocol encoding
    if "protocol" in work.columns:
        work["protocol"] = work["protocol"].astype(str).str.upper()
        proto_map = {p: i for i, p in enumerate(sorted(work["protocol"].unique()))}
        work["protocol_enc"] = work["protocol"].map(proto_map)
    # Start with all numeric columns
    numeric_cols = list(work.select_dtypes(include=["number"]).columns)
    # Add known numeric-likes if still missing (coerce)
    candidate_extra = ["src_port", "dst_port", "byte_count", "packet_count", "protocol_enc"]
    for c in candidate_extra:
        if c in work.columns and c not in numeric_cols:
            with pd.option_context("mode.chained_assignment", None):
                work[c] = pd.to_numeric(work[c], errors="coerce").fillna(0)
            numeric_cols.append(c)
    # Remove label from scaling
    if "label" in numeric_cols:
        numeric_cols.remove("label")
    scaler: Any = StandardScaler() if scaler_type == "standard" else MinMaxScaler()
    if numeric_cols:
        # Coerce and clean extreme / infinite values
        arr = work[numeric_cols].apply(pd.to_numeric, errors="coerce")
        # Replace inf/-inf with nan then fill with column medians
        arr.replace([np.inf, -np.inf], np.nan, inplace=True)
        medians = arr.median(numeric_only=True)
        arr = arr.fillna(medians).fillna(0)
        # Cap extreme outliers at 99.5 percentile to stabilize scaling
        caps = arr.quantile(0.995)
        for c in numeric_cols:
            cap = caps.get(c)
            if pd.notna(cap):
                arr[c] = np.clip(arr[c], a_min=None, a_max=cap)
        try:
            work[numeric_cols] = scaler.fit_transform(arr)
        except Exception:
            # As last resort fill remaining NaNs with 0 and retry
            arr = arr.fillna(0)
            work[numeric_cols] = scaler.fit_transform(arr)
    return work, scaler


def prepare_train_test(df: pd.DataFrame, label_col: str = "label", test_size: float = 0.2, random_state: int = 42):
    if df.empty or label_col not in df.columns:
        return df, df, [], []
    X = df.drop(columns=[label_col])
    y = df[label_col]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=random_state, stratify=y)
    return X_train, X_test, y_train, y_test


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """Return a minimal feature subset; extend later."""
    if df.empty:
        return df
    feature_cols = [c for c in df.columns if c not in {"label"}]
    return df[feature_cols].copy()


# ----------------------------------------------------------------------------------
# New automatic preprocessing pipeline
# ----------------------------------------------------------------------------------
def _select_label_column(df: pd.DataFrame) -> str:
    candidates = ["label", "Label", "attack_cat", "class", "target"]
    for c in candidates:
        if c in df.columns:
            return c
    return "label"  # will be synthesized


def _create_binary_label(series: pd.Series) -> pd.Series:
    # Normalize to string lower
    s = series.astype(str).str.lower().str.strip()
    benign_tokens = {"benign", "normal", "0", "clean", "background"}
    return (~s.isin(benign_tokens)).astype(int)


def _drop_irrelevant_columns(df: pd.DataFrame) -> pd.DataFrame:
    cols_to_drop = set()
    for col in df.columns:
        if col in EXACT_DROP:
            cols_to_drop.add(col)
            continue
        for pat in DROP_PATTERNS:
            if re.search(pat, col.lower()):
                cols_to_drop.add(col)
                break
    return df.drop(columns=list(cols_to_drop & set(df.columns)), errors='ignore')


def _split_cat_num(df: pd.DataFrame, label_col: str) -> Tuple[pd.DataFrame, List[str], List[str]]:
    cat_cols = []
    num_cols = []
    for c in df.columns:
        if c == label_col:
            continue
        if df[c].dtype == object or df[c].dtype.name.startswith("category"):
            cat_cols.append(c)
        else:
            num_cols.append(c)
    return df, cat_cols, num_cols


def auto_preprocess(df: pd.DataFrame, scaler_type: str = "standard", one_hot_max_unique: int = 30,
                    apply_smote: bool = True, test_size: float = 0.2, random_state: int = 42) -> Dict[str, Any]:
    """Full automatic pipeline.

    Returns dict with X_train, X_test, y_train, y_test, artifacts (scaler, feature_list, meta).
    """
    out: Dict[str, Any] = {}
    if df.empty:
        out.update({"X_train": df, "X_test": df, "y_train": [], "y_test": [], "artifacts": {}})
        return out
    df = basic_clean(df)
    label_col = _select_label_column(df)
    if label_col not in df.columns:
        # synthesize using byte_count threshold if available
        if "byte_count" in df.columns:
            thresh = df["byte_count"].median()
            df[label_col] = (df["byte_count"] > thresh).astype(int)
        else:
            df[label_col] = 0
    # If label non-numeric: binarize
    if not pd.api.types.is_numeric_dtype(df[label_col]):
        df[label_col] = _create_binary_label(df[label_col])
    df = _drop_irrelevant_columns(df)
    # Split cat/num
    df, cat_cols, num_cols = _split_cat_num(df, label_col)
    # Coerce numeric & initial fill
    if num_cols:
        for c in num_cols:
            df[c] = pd.to_numeric(df[c], errors="coerce")
        # Replace inf with NaN then fill with median
        df[num_cols] = df[num_cols].replace([np.inf, -np.inf], np.nan)
        medians = df[num_cols].median(numeric_only=True)
        df[num_cols] = df[num_cols].fillna(medians).fillna(0)
        # Clip extreme outliers at 99.9 percentile to prevent exploding scale
        try:
            caps = df[num_cols].quantile(0.999)
            for c in num_cols:
                cap = caps.get(c)
                if pd.notna(cap):
                    df[c] = np.clip(df[c], a_min=None, a_max=cap)
        except Exception:
            pass
    # Reduce cardinality: if categorical unique ratio too high, drop
    kept_cat = []
    high_card_dropped = []
    for c in cat_cols:
        uniq = df[c].nunique()
        if uniq == 0:
            continue
        if uniq > one_hot_max_unique:
            high_card_dropped.append(c)
            continue
        kept_cat.append(c)
    # One-hot encode kept categorical
    if kept_cat:
        df[kept_cat] = df[kept_cat].astype(str).fillna("UNK")
        dummies = pd.get_dummies(df[kept_cat], prefix=kept_cat, dummy_na=False)
        df = pd.concat([df.drop(columns=kept_cat), dummies], axis=1)
    # Safety: drop any residual non-numeric, non-label columns (unexpected objects)
    residual_obj = [c for c in df.columns if c != label_col and df[c].dtype == object]
    if residual_obj:
        try:
            # Attempt one-hot if low cardinality else drop
            low_card = [c for c in residual_obj if df[c].nunique() <= one_hot_max_unique]
            if low_card:
                df[low_card] = df[low_card].astype(str).fillna("UNK")
                dummies2 = pd.get_dummies(df[low_card], prefix=low_card, dummy_na=False)
                df = pd.concat([df.drop(columns=low_card), dummies2], axis=1)
            # Recompute residuals
            residual_obj = [c for c in df.columns if c != label_col and df[c].dtype == object]
            if residual_obj:
                df = df.drop(columns=residual_obj)
        except Exception:
            # On any failure, drop these columns to guarantee numeric-only features
            df = df.drop(columns=residual_obj, errors='ignore')
    # Scale numeric (re-detect numeric after dummies) excluding label
    feature_cols = [c for c in df.columns if c != label_col]
    num_cols_final = list(df[feature_cols].select_dtypes(include=["number"]).columns)
    scaler: Any = StandardScaler() if scaler_type == "standard" else MinMaxScaler()
    if num_cols_final:
        # Sanitize again post one-hot merge
        numeric_block = df[num_cols_final].replace([np.inf, -np.inf], np.nan)
        block_medians = numeric_block.median(numeric_only=True)
        numeric_block = numeric_block.fillna(block_medians).fillna(0)
        try:
            block_caps = numeric_block.quantile(0.999)
            for c in num_cols_final:
                cap = block_caps.get(c)
                if pd.notna(cap):
                    numeric_block[c] = np.clip(numeric_block[c], a_min=None, a_max=cap)
        except Exception:
            pass
        df[num_cols_final] = scaler.fit_transform(numeric_block.astype(float))
    X = df[feature_cols]
    y = df[label_col]
    # For very small datasets where a class has <2 samples, disable stratification
    disable_strat = False
    try:
        class_counts = y.value_counts()
        if (class_counts < 2).any() or len(class_counts) < 2:
            disable_strat = True
    except Exception:
        disable_strat = True
    if disable_strat:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=random_state)
    else:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, stratify=y, random_state=random_state)
    smote_applied = False
    if apply_smote and _HAS_SMOTE:
        # Only apply if minority class proportion < 0.3
        class_ratio = y_train.mean() if y_train.mean() < 0.5 else 1 - y_train.mean()
        if class_ratio < 0.3:
            try:
                sm = SMOTE(random_state=random_state)
                X_train, y_train = sm.fit_resample(X_train, y_train)
                smote_applied = True
            except Exception:
                smote_applied = False
    artifacts = {
        "scaler": scaler,
        "feature_list": list(X.columns),
        "label_col": label_col,
        "dropped_high_card": high_card_dropped,
        "smote_applied": smote_applied,
        "feature_stats": {
            c: {
                "mean": float(df[c].mean()),
                "std": float(df[c].std(ddof=0) if df[c].std(ddof=0) == df[c].std(ddof=0) else 0.0),
                "min": float(df[c].min()),
                "max": float(df[c].max()),
            } for c in num_cols_final
        }
    }
    out.update({
        "X_train": X_train,
        "X_test": X_test,
        "y_train": y_train,
        "y_test": y_test,
        "artifacts": artifacts,
    })
    return out
