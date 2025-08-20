"""Unified baseline training script.

Aggregates multiple network intrusion / APT datasets (if present) under data/:
 - APT-Dataset (by Cho Do Xuan)/flowFeatures.csv
 - CIC-IDS2017 (Network Intrusion Evaluation Dataset)/*.csv
 - UNSW-NB15/*.csv (prefers provided train/test splits)

Produces:
 models/RandomForest.joblib
 models/XGBoost.joblib
 models/scaler.joblib

Usage (PowerShell):
  python train_baseline.py --models RandomForest XGBoost
"""
from __future__ import annotations
import argparse
from pathlib import Path
import pandas as pd
from typing import List

from ml_models.train import train_models
from ml_models.preprocessing import basic_clean

DATA_DIR = Path(__file__).parent / "data"


def find_datasets() -> List[Path]:
    csvs: List[Path] = []
    # APT dataset
    apt_dir = DATA_DIR / "APT-Dataset (by Cho Do Xuan)"
    if apt_dir.exists():
        csvs.extend(sorted(apt_dir.glob("*.csv")))
    cic_dir = DATA_DIR / "CIC-IDS2017 (Network Intrusion Evaluation Dataset)"
    if cic_dir.exists():
        csvs.extend(sorted(cic_dir.glob("*.csv")))
    unsw_dir = DATA_DIR / "UNSW-NB15"
    if unsw_dir.exists():
        # prefer provided train set if present else all
        train_files = list(unsw_dir.glob("*training-set*.csv"))
        if train_files:
            csvs.extend(train_files)
        else:
            csvs.extend(sorted(unsw_dir.glob("*.csv")))
    return csvs


def load_and_union(csvs: List[Path], sample_limit: int | None = 200000) -> pd.DataFrame:
    frames: List[pd.DataFrame] = []
    for p in csvs:
        try:
            df = pd.read_csv(
                p,
                low_memory=False,
                on_bad_lines='skip',
            )
        except Exception:
            continue
        # Standardize label column naming heuristically
        possible_labels = ["label", "Label", "attack_cat", "class"]
        label_col = None
        for c in possible_labels:
            if c in df.columns:
                label_col = c
                break
        if label_col and label_col != "label":
            df.rename(columns={label_col: "label"}, inplace=True)
        # Basic normalization of IP fields if present
        for ip_col in ["src_ip", "Source IP", "Src IP", "Dst IP", "Destination IP", "dst_ip"]:
            if ip_col in df.columns:
                std_name = ip_col.lower().replace(" ", "_").replace("source", "src").replace("destination", "dst")
                df.rename(columns={ip_col: std_name}, inplace=True)
        # Limit oversized frames
        if sample_limit and len(df) > sample_limit:
            # Down-sample early to reduce memory footprint
            df = df.sample(sample_limit, random_state=42)
        # Drop obviously empty or all-null columns
        null_frac = df.isna().mean()
        drop_cols = [c for c, frac in null_frac.items() if frac >= 0.995]
        if drop_cols:
            df.drop(columns=drop_cols, inplace=True, errors='ignore')
        frames.append(df)
    if not frames:
        return pd.DataFrame()
    union = pd.concat(frames, axis=0, ignore_index=True, sort=False)
    union = basic_clean(union)
    return union


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--models", nargs="+", default=["RandomForest", "XGBoost"], help="Models to train")
    parser.add_argument("--output_dir", default="models", help="Directory to store trained models")
    parser.add_argument("--sample_limit", type=int, default=150000, help="Per-file sample cap to control memory")
    args = parser.parse_args()

    csvs = find_datasets()
    if not csvs:
        print("No dataset CSV files found under data/. Aborting.")
        return
    print(f"Discovered {len(csvs)} dataset files. Loading & merging...")
    df = load_and_union(csvs, sample_limit=args.sample_limit)
    print(f"Unified dataset shape: {df.shape}")
    if df.empty:
        print("Unified dataset empty after loading. Aborting.")
        return
    # Ensure a label column exists; if not create synthetic
    if "label" not in df.columns:
        if "byte_count" in df.columns:
            thresh = df["byte_count"].median()
            df["label"] = (df["byte_count"] > thresh).astype(int)
        else:
            df["label"] = 0
    # Global cap to keep quick iteration manageable
    GLOBAL_CAP = 120000
    if len(df) > GLOBAL_CAP:
        df = df.sample(GLOBAL_CAP, random_state=42)
        print(f"Down-sampled unified dataset to {len(df)} rows for faster training.")
    merged_path = Path(args.output_dir) / "merged_training_snapshot.csv"
    # Write only a tiny head snapshot for reference
    try:
        merged_path.parent.mkdir(parents=True, exist_ok=True)
        df.head(5000).to_csv(merged_path, index=False)
        print(f"Wrote preview snapshot (first 5k rows) to {merged_path}")
    except Exception:
        pass

    config = {
        "dataset_path": str(merged_path),  # kept for reference
        "models": args.models,
        "output_dir": args.output_dir,
        "dataframe": df,
    }
    trained = train_models(config)
    if not trained:
        print("Training produced no models.")
    else:
        print(f"Trained models: {', '.join(trained.keys())}")


if __name__ == "__main__":
    main()
