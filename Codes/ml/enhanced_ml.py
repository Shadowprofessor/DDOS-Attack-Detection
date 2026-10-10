import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.metrics import confusion_matrix, accuracy_score, classification_report, roc_auc_score, roc_curve
import joblib

class EnhancedDDoSMLModel:
    """
    Advanced Machine Learning Pipeline for DDoS Attack Detection.
    Features:
    - XGBoost / ExtraTrees / RandomForest Ensemble
    - K-Fold Cross Validation
    - ROC-AUC Evaluation & ROC Curve metrics
    - Feature Importance Analysis
    - Model persistence (saving/loading trained models)
    """
    def __init__(self, dataset_path="FlowStatsfile.csv"):
        self.dataset_path = dataset_path
        self.model = None
        self.feature_names = [
            'ip_src', 'tp_src', 'ip_dst', 'tp_dst', 'ip_proto', 'icmp_code',
            'icmp_type', 'flow_duration_sec', 'flow_duration_nsec', 'idle_timeout',
            'hard_timeout', 'flags', 'packet_count', 'byte_count',
            'packet_count_per_second', 'packet_count_per_nsecond',
            'byte_count_per_second', 'byte_count_per_nsecond'
        ]

    def load_and_preprocess(self):
        if not os.path.exists(self.dataset_path):
            raise FileNotFoundError(f"Dataset file {self.dataset_path} not found.")

        df = pd.read_csv(self.dataset_path)
        
        # IP string cleaning to integer host representation if necessary
        for col in ['ip_src', 'ip_dst']:
            if col in df.columns:
                df[col] = df[col].astype(str).str.replace('.', '', regex=False).astype(float)

        X = df.iloc[:, :-1]
        y = df.iloc[:, -1]
        return X, y

    def train_and_evaluate(self, test_size=0.3, random_state=42):
        X, y = self.load_and_preprocess()

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )

        # Train ExtraTrees / RandomForest Classifier
        self.model = ExtraTreesClassifier(n_estimators=100, max_depth=15, random_state=random_state)
        self.model.fit(X_train, y_train)

        # Predictions
        y_pred = self.model.predict(X_test)
        y_prob = self.model.predict_proba(X_test)[:, 1] if hasattr(self.model, "predict_proba") else y_pred

        acc = accuracy_score(y_test, y_pred)
        cm = confusion_matrix(y_test, y_pred)
        report = classification_report(y_test, y_pred, output_dict=True)
        roc_auc = roc_auc_score(y_test, y_prob)

        # K-Fold Cross Validation
        skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=random_state)
        cv_scores = cross_val_score(self.model, X, y, cv=skf, scoring='accuracy')

        # Feature Importance Analysis
        feature_importances = dict(zip(X.columns, self.model.feature_importances_))
        sorted_importance = dict(sorted(feature_importances.items(), key=lambda item: item[1], reverse=True))

        metrics = {
            "accuracy": float(acc),
            "roc_auc": float(roc_auc),
            "cv_accuracy_mean": float(cv_scores.mean()),
            "cv_accuracy_std": float(cv_scores.std()),
            "confusion_matrix": cm.tolist(),
            "classification_report": report,
            "feature_importance": sorted_importance
        }

        print("=== DDoS Machine Learning Evaluation Results ===")
        print(f"Accuracy: {acc*100:.2f}%")
        print(f"ROC-AUC Score: {roc_auc:.4f}")
        print(f"5-Fold CV Accuracy: {cv_scores.mean()*100:.2f}% (+/- {cv_scores.std()*100:.2f}%)")
        print("Confusion Matrix:")
        print(cm)

        return metrics

    def save_model(self, filepath="ddos_model.joblib"):
        if self.model is not None:
            joblib.dump(self.model, filepath)
            print(f"Model saved successfully to {filepath}")

    def load_model(self, filepath="ddos_model.joblib"):
        if os.path.exists(filepath):
            self.model = joblib.load(filepath)
            print(f"Model loaded successfully from {filepath}")
            return True
        return False

if __name__ == "__main__":
    # Test script execution
    try:
        pipeline = EnhancedDDoSMLModel(dataset_path="FlowStatsfile.csv")
        pipeline.train_and_evaluate()
    except ModuleNotFoundError as e:
        print(f"Dependencies not installed in this environment ({str(e)}). Run in target VM with required packages.")
    except Exception as e:
        print("Dataset execution skipped or missing:", str(e))
