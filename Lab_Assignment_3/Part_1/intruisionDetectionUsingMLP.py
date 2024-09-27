import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

# Load the dataset
data = pd.read_csv('./Lab_Assignment_3/Part_1/dataset/NSL_KDD_Train.csv', header=None)

# Define column names
column_names = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate'
]
data.columns = column_names + [f'col_{i}' for i in range(len(column_names), len(data.columns)-1)] + ['class']

# Select features
selected_features = column_names
X = data[selected_features]
y = data['class']

# Split the data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Define preprocessing steps
numeric_features = ['duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 
                    'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 
                    'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 
                    'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 
                    'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 
                    'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate']

categorical_features = ['protocol_type', 'service', 'flag']

preprocessor = ColumnTransformer(
    transformers=[
        ('num', StandardScaler(), numeric_features),
        ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
    ])

# Create a pipeline
clf = Pipeline([
    ('preprocessor', preprocessor),
    ('classifier', MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=300, random_state=42))
])

# Fit the model
clf.fit(X_train, y_train)

# Make predictions
y_pred = clf.predict(X_test)

# Evaluate the model
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:")
print(classification_report(y_test, y_pred))
