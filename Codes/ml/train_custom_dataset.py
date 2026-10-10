import os
import sys
import argparse
import time
import joblib
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
os.makedirs(MODELS_DIR, exist_ok=True)

def load_and_preprocess(file_path):
    print(f"[*] Loading dataset from: {file_path} ...")
    if os.path.isdir(file_path):
        csv_files = [os.path.join(file_path, f) for f in os.listdir(file_path) if f.endswith('.csv')]
        print(f"[*] Found {len(csv_files)} CSV files in directory. Combining...")
        dfs = [pd.read_csv(f, low_memory=False) for f in csv_files]
        df = pd.concat(dfs, ignore_index=True)
    else:
        ext = os.path.splitext(file_path)[1].lower()
        if ext == '.csv':
            df = pd.read_csv(file_path, low_memory=False)
        elif ext in ['.parquet', '.pq']:
            df = pd.read_parquet(file_path)
        else:
            raise ValueError(f"Unsupported file format: {ext}")

    print(f"[OK] Raw dataset shape: {df.shape}")

    # Strip whitespace from column names
    df.columns = df.columns.str.strip()

    # Find target column (commonly 'Label', 'label', 'Class', 'attack', 'category')
    target_col = None
    for candidate in ['Label', 'label', 'Class', 'class', 'Attack', 'attack', 'category', 'Category', 'result']:
        if candidate in df.columns:
            target_col = candidate
            break
    
    if target_col is None:
        target_col = df.columns[-1]

    print(f"[*] Target column identified as: '{target_col}'")

    # Separate X and y
    y_raw = df[target_col]
    X_raw = df.drop(columns=[target_col])

    # Convert binary/multiclass target to 0 (benign) / 1 (attack)
    if y_raw.dtype == object or isinstance(y_raw.iloc[0], str):
        y = y_raw.astype(str).str.upper().apply(
            lambda v: 0 if any(b in v for b in ['BENIGN', 'NORMAL', '0', 'GOOD']) else 1
        ).values
    else:
        y = (y_raw != 0).astype(int).values

    # Convert string / IP / identifier columns to numeric
    cols_to_drop = []
    for col in X_raw.columns:
        if X_raw[col].dtype == object or isinstance(X_raw[col].iloc[0], str):
            # Try removing dots (for IP addresses) and converting to float
            s_clean = X_raw[col].astype(str).str.replace('.', '', regex=False)
            numeric_s = pd.to_numeric(s_clean, errors='coerce')
            
            if numeric_s.notna().sum() > 0.5 * len(numeric_s):
                X_raw[col] = numeric_s.fillna(0)
            else:
                try:
                    le = LabelEncoder()
                    X_raw[col] = le.fit_transform(X_raw[col].astype(str))
                except Exception:
                    cols_to_drop.append(col)

    if cols_to_drop:
        print(f"[*] Dropping non-numeric columns: {cols_to_drop[:5]}...")
        X_raw = X_raw.drop(columns=cols_to_drop)

    # Fill NaN / Inf
    X_raw = X_raw.replace([np.inf, -np.inf], np.nan).fillna(0)

    # Subsample if dataset is larger than 20,000 rows for fast laptop training
    MAX_SAMPLES = 20000
    if len(X_raw) > MAX_SAMPLES:
        print(f"[*] Subsampling {MAX_SAMPLES} balanced rows from {len(X_raw)} total rows for fast local execution...")
        idx_sample = np.random.choice(len(X_raw), MAX_SAMPLES, replace=False)
        X = X_raw.iloc[idx_sample].values.astype('float64')
        y = y[idx_sample]
    else:
        X = X_raw.values.astype('float64')

    print(f"[OK] Preprocessed dataset: {X.shape[0]} samples, {X.shape[1]} features | Class distribution: Benign={np.sum(y==0)}, Attack={np.sum(y==1)}")
    return X, y, list(X_raw.columns)

def train_and_evaluate(dataset_path, model_filter=None):
    print("==========================================================================")
    print(f"      DDoS SDN Machine Learning Model Training & Evaluation Benchmark     ")
    print("==========================================================================")

    X, y, feature_names = load_and_preprocess(dataset_path)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y if len(np.unique(y)) > 1 else None
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Save scaler
    scaler_path = os.path.join(MODELS_DIR, "feature_scaler.pkl")
    joblib.dump(scaler, scaler_path)

    all_models = {
        "RandomForest": (RandomForestClassifier(n_estimators=100, criterion='entropy', random_state=42, n_jobs=-1), False),
        "DecisionTree": (DecisionTreeClassifier(criterion='entropy', random_state=42), False),
        "ExtraTrees": (ExtraTreesClassifier(n_estimators=100, random_state=42, n_jobs=-1), False),
        "KNN": (KNeighborsClassifier(n_neighbors=5, n_jobs=-1), True),
        "LogisticRegression": (LogisticRegression(max_iter=1000, random_state=42), True),
        "NaiveBayes": (GaussianNB(), True),
        "SVM": (SVC(kernel='rbf', C=1.0, random_state=42), True)
    }

    if model_filter:
        models = {k: v for k, v in all_models.items() if k.lower() == model_filter.lower()}
    else:
        models = all_models

    results = []
    print("\n[*] Starting Model Training Phase...\n")

    for name, (clf, use_scaling) in models.items():
        X_tr = X_train_scaled if use_scaling else X_train
        X_te = X_test_scaled if use_scaling else X_test

        t0 = time.time()
        clf.fit(X_tr, y_train)
        t_train = (time.time() - t0) * 1000

        t1 = time.time()
        y_pred = clf.predict(X_te)
        t_infer = (time.time() - t1) * 1000

        acc = accuracy_score(y_test, y_pred) * 100
        prec = precision_score(y_test, y_pred, zero_division=0) * 100
        rec = recall_score(y_test, y_pred, zero_division=0) * 100
        f1 = f1_score(y_test, y_pred, zero_division=0) * 100
        cm = confusion_matrix(y_test, y_pred, labels=[0, 1])

        # Save model checkpoint
        save_path = os.path.join(MODELS_DIR, f"{name}_model.pkl")
        joblib.dump(clf, save_path)

        results.append({
            "Model": name,
            "Accuracy": f"{acc:.2f}%",
            "Precision": f"{prec:.2f}%",
            "Recall": f"{rec:.2f}%",
            "F1-Score": f"{f1:.2f}%",
            "Train Latency": f"{t_train:.1f}ms",
            "Infer Latency": f"{t_infer:.1f}ms",
            "Saved Checkpoint": os.path.basename(save_path)
        })

        print(f"[OK] [{name}] Acc: {acc:.2f}% | F1: {f1:.2f}% | Train Time: {t_train:.1f}ms | ConfMatrix: TN={cm[0,0]}, FP={cm[0,1]}, FN={cm[1,0]}, TP={cm[1,1]}")

    print("\n==========================================================================")
    print("                     SUMMARY PERFORMANCE REPORT                           ")
    print("==========================================================================")
    res_df = pd.DataFrame(results)
    print(res_df.to_string(index=False))
    print("==========================================================================")
    print(f"[OK] Trained models saved in: {MODELS_DIR}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train & Benchmark Machine Learning DDoS Detection Models")
    parser.add_argument("--dataset", type=str, default=None, help="Path to CSV or Parquet dataset file")
    parser.add_argument("--model", type=str, default=None, help="Train specific model (e.g. RandomForest, KNN, DecisionTree)")
    args = parser.parse_args()

    dataset_file = args.dataset
    if not dataset_file or not os.path.exists(dataset_file):
        # Default search paths
        candidates = [
            os.path.join(MODELS_DIR, "..", "datasets", "cicddos2019.csv"),
            os.path.join(MODELS_DIR, "..", "datasets", "insdn.csv"),
            os.path.join(MODELS_DIR, "..", "datasets", "Syn-training.parquet"),
            "FlowStatsfile.csv"
        ]
        for c in candidates:
            if os.path.exists(c):
                dataset_file = c
                break

    if not dataset_file or not os.path.exists(dataset_file):
        print("[!] No dataset found. Running dataset downloader first...")
        import download_datasets
        download_datasets.download_dataset("cicddos2019")
        dataset_file = os.path.join(MODELS_DIR, "..", "datasets", "cicddos2019.csv")

    train_and_evaluate(dataset_file, args.model)
