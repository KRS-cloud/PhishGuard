import os
import pandas as pd
import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
from utils.feature_extraction import extract_features

def train_engine():
    # 1. Paths configuration
    dataset_path = os.path.join('dataset', 'phishing_dataset.csv')
    model_dir = 'model'
    model_path = os.path.join(model_dir, 'phishing_model.pkl')
    
    print("🔄 Loading dataset...")
    if not os.path.exists(dataset_path):
        print(f"❌ Error: Could not find dataset at {dataset_path}")
        return
        
    df = pd.read_csv(dataset_path)
    
    print("⚙️ Extracting numerical features from URLs...")
    # Convert every text URL in our CSV into a numeric feature row using our utility
    X = np.array([extract_features(url) for url in df['url']])
    y = df['label'].values
    
    print("🌲 Training the Random Forest Classifier...")
    # Initialize the model with 100 trees
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    
    # 2. Ensure model directory exists and save the trained brain
    if not os.path.exists(model_dir):
        os.makedirs(model_dir)
        
    with open(model_path, 'wb') as file:
        pickle.dump(model, file)
        
    print(f"🎯 Success! Model trained and saved inside: {model_path}")

if __name__ == '__main__':
    train_engine()