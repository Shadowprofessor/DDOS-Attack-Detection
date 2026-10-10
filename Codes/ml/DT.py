import os
from datetime import datetime
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import confusion_matrix, accuracy_score

class MachineLearning():
    def __init__(self):
        print("Loading dataset for Decision Tree...")
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
            from generate_dataset import generate_sample_dataset
            generate_sample_dataset()
            dataset_path = "FlowStatsfile.csv"

        self.flow_dataset = pd.read_csv(dataset_path)

        for col in ['ip_src', 'ip_dst']:
            if col in self.flow_dataset.columns:
                self.flow_dataset[col] = self.flow_dataset[col].astype(str).str.replace('.', '', regex=False).astype(float)

    def flow_training(self):
        print("Decision Tree Flow Training ...")
        X_flow = self.flow_dataset.iloc[:, :-1].values.astype('float64')
        y_flow = self.flow_dataset.iloc[:, -1].values

        X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(
            X_flow, y_flow, test_size=0.25, random_state=42
        )

        classifier = DecisionTreeClassifier(criterion='entropy', random_state=42)
        flow_model = classifier.fit(X_flow_train, y_flow_train)
        y_flow_pred = flow_model.predict(X_flow_test)

        print("------------------------------------------------------------------------------")
        print("Confusion Matrix:")
        cm = confusion_matrix(y_flow_test, y_flow_pred)
        print(cm)

        acc = accuracy_score(y_flow_test, y_flow_pred)
        print("Success Accuracy = {0:.2f} %".format(acc * 100))
        print("Fail Accuracy    = {0:.2f} %".format((1.0 - acc) * 100))
        print("------------------------------------------------------------------------------")

def main():
    start = datetime.now()
    ml = MachineLearning()
    ml.flow_training()
    end = datetime.now()
    print("Training time: ", (end - start))

if __name__ == "__main__":
    main()