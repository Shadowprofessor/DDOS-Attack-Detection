#!/usr/bin/env python3
"""
ML Models Train and Evaluate Runner (Entry Point Wrapper)
Trains and evaluates all 7 Machine Learning models (Random Forest, Decision Tree,
KNN, Extra Trees, Logistic Regression, SVM, Naive Bayes) on FlowStatsfile.csv.
"""
import os
import sys

# Add Codes/ml to sys.path
ML_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ml"))
if ML_DIR not in sys.path:
    sys.path.insert(0, ML_DIR)

if __name__ == "__main__":
    from evaluate_all_models import evaluate_all_models
    evaluate_all_models()
