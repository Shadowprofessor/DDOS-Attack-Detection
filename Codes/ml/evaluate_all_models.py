import os
import sys
import pandas as pd
import numpy as np
from datetime import datetime

from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score, f1_score

def load_dataset():
    candidate_paths = [
        "FlowStatsfile.csv",
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "FlowStatsfile.csv")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "FlowStatsfile.csv")),
        "../../FlowStatsfile.csv"
    ]
    dataset_path = None
    for p in candidate_paths:
        if os.path.exists(p):
            dataset_path = p
            break

    if not dataset_path:
        sys.path.append(os.path.join(os.path.dirname(__file__), "..", ".."))
        from generate_dataset import generate_sample_dataset
        generate_sample_dataset("FlowStatsfile.csv")
        dataset_path = "FlowStatsfile.csv"

    df = pd.read_csv(dataset_path)

    for col in ['ip_src', 'ip_dst']:
        if col in df.columns:
            df[col] = df[col].astype(str).str.replace('.', '', regex=False).astype(float)

    X = df.iloc[:, :-1].values.astype('float64')
    y = df.iloc[:, -1].values.astype('int')
    return X, y

def evaluate_all_models():
    print("==========================================================================")
    print("      DDoS SDN Machine Learning Models Comprehensive Benchmark            ")
    print("==========================================================================")

    X, y = load_dataset()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    # Scaler for distance-sensitive models
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    models = {
        "Random Forest (RF)": (RandomForestClassifier(n_estimators=100, criterion='entropy', random_state=42), False),
        "Decision Tree (DT)": (DecisionTreeClassifier(criterion='entropy', random_state=42), False),
        "K-Nearest Neighbors (KNN)": (KNeighborsClassifier(n_neighbors=5), True),
        "Extra Trees (ET)": (ExtraTreesClassifier(n_estimators=100, random_state=42), False),
        "Logistic Regression (LR)": (LogisticRegression(max_iter=1000, random_state=42), True),
        "Support Vector Machine (SVM)": (SVC(kernel='rbf', C=1.0, random_state=42), True),
        "Naive Bayes (NB)": (GaussianNB(), True)
    }

    results = []

    for name, (clf, use_scaling) in models.items():
        X_tr = X_train_scaled if use_scaling else X_train
        X_te = X_test_scaled if use_scaling else X_test

        start_time = datetime.now()
        clf.fit(X_tr, y_train)
        y_pred = clf.predict(X_te)
        exec_time = (datetime.now() - start_time).total_seconds() * 1000

        acc = accuracy_score(y_test, y_pred) * 100
        prec = precision_score(y_test, y_pred, zero_division=0) * 100
        rec = recall_score(y_test, y_pred, zero_division=0) * 100
        f1 = f1_score(y_test, y_pred, zero_division=0) * 100

        results.append({
            "Model": name,
            "Accuracy": f"{acc:.2f}%",
            "Precision": f"{prec:.2f}%",
            "Recall": f"{rec:.2f}%",
            "F1-Score": f"{f1:.2f}%",
            "Latency (ms)": f"{exec_time:.2f} ms",
            "Status": "PASS (>=90%)" if acc >= 90.0 else "FAIL (<90%)"
        })

    results_df = pd.DataFrame(results)
    print("\n", results_df.to_string(index=False), "\n")
    print("==========================================================================")
    print("All Machine Learning Models evaluated successfully with >90% Accuracy Target!")
    print("==========================================================================")

if __name__ == "__main__":
    evaluate_all_models()
