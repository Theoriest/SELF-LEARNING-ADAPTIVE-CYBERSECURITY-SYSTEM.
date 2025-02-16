import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestRegressor
from transformers import BertTokenizer, BertForSequenceClassification
import torch
import joblib

# Load the data
df = pd.read_csv("/workspace/SELF-LEARNING-ADAPTIVE-CYBERSECURITY-SYSTEM./Data/csv_files/cve_data.csv")

# Handle missing values
df.ffill(inplace=True)

# Load pre-trained BERT model and tokenizer
tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
model = BertForSequenceClassification.from_pretrained('bert-base-uncased', num_labels=3)

# Define a function to classify descriptions
def classify_cia(description):
    inputs = tokenizer(description, return_tensors='pt', truncation=True, padding=True, max_length=512)
    outputs = model(**inputs)
    logits = outputs.logits
    predicted_class = torch.argmax(logits, dim=1).item()
    if predicted_class == 0:
        return 'Confidentiality'
    elif predicted_class == 1:
        return 'Integrity'
    elif predicted_class == 2:
        return 'Availability'
    else:
        return 'Other'

# Apply the classification function to the Description column
df['CIA_Class'] = df['Description'].apply(classify_cia)

# Split data into features and target
features = df.drop(columns=['CVSS_Score'])
target = df['CVSS_Score']

# Split into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(features, target, test_size=0.2, random_state=42)

# Textual feature extraction
text_transformer = Pipeline(steps=[
    ('tfidf', TfidfVectorizer(max_features=1000))
])

# Categorical feature encoding
categorical_features = ['CIA_Class']
categorical_transformer = Pipeline(steps=[
    ('onehot', OneHotEncoder(handle_unknown='ignore'))
])

# Combine transformers
preprocessor = ColumnTransformer(
    transformers=[
        ('text', text_transformer, 'Description'),
        ('cat', categorical_transformer, categorical_features)
    ]
)

# Create a pipeline with preprocessor and model
model = Pipeline(steps=[
    ('preprocessor', preprocessor),
    ('regressor', RandomForestRegressor(n_estimators=100, random_state=42))
])

# Train the model
model.fit(X_train, y_train)

# Save the trained model to a file
joblib.dump(model, 'Susano_1.pkl')
print("Model saved to trained_model.pkl")

# Predict missing values
df['Predicted_CVSS_Score'] = model.predict(features)

# Save the updated DataFrame to CSV file
df.to_csv("/workspace/SELF-LEARNING-ADAPTIVE-CYBERSECURITY-SYSTEM./Data/csv_files/cve_data_transformer_updated.csv", mode='w', header=True, index=False)
print("Data updated and saved to cve_data_transformer_updated.csv")