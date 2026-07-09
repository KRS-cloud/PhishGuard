import os
import pickle
from flask import Flask, render_template, request
from utils.feature_extraction import extract_features

# 1. Initialize the Flask application instance
app = Flask(__name__)

# Define paths dynamically so Windows handles them correctly
MODEL_PATH = os.path.join('model', 'phishing_model.pkl')
ml_model = None

def load_model():
    """Loads our pre-trained machine learning model binary into server memory."""
    global ml_model
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, 'rb') as file:
            ml_model = pickle.load(file)
        print("💡 [SUCCESS]: Random Forest Model loaded into Flask memory.")
    else:
        print("❌ [CRITICAL ERROR]: phishing_model.pkl not found! Run train_model.py first.")

# Trigger model load when server starts
load_model()


# 2. Route: Homepage View
@app.route('/', methods=['GET'])
def home():
    # Renders the initial layout page without any result indicators
    return render_template('index.html', scanned=False)


# 3. Route: Processing & Prediction Logic API
@app.route('/predict', methods=['POST'])
def predict():
    if ml_model is None:
        return render_template('index.html', error="Prediction engine is offline. Re-run model training.")
    
    # Extract data from the HTML form input text field
    raw_url = request.form.get('url_input', '').strip()
    
    if not raw_url:
        return render_template('index.html', error="Please enter a valid URL to scan.")
    
    try:
        # Step A: Convert the raw text URL into our 6-dimension numeric feature array
        numeric_features = extract_features(raw_url)
        
        # Step B: Pass feature array to model (reshape to 2D array as expected by Scikit-Learn)
        prediction = ml_model.predict([numeric_features])[0]
        probabilities = ml_model.predict_proba([numeric_features])[0]
        
        # Step C: Compute distinct safety percentage metrics
        phishing_probability = round(probabilities[1] * 100, 2)
        safe_probability = round(probabilities[0] * 100, 2)
        
        # Step D: Construct user-friendly presentation strings based on the prediction
        if prediction == 1:
            status = "DANGEROUS"
            color = "danger"  # maps to red styling in CSS
            message = f"PhishGuard has flagged this link as malicious. Highly suspicious structural layout ({phishing_probability}% risk score)."
        else:
            status = "SAFE"
            color = "success"  # maps to green styling in CSS
            message = f"This website looks clean and conforms to standard URL structural architecture ({safe_probability}% safety rating)."
            
        # Step E: Send parameters directly back to index.html using Jinja2 dynamic rendering
        return render_template(
            'index.html',
            url=raw_url,
            status=status,
            color=color,
            message=message,
            risk_score=phishing_probability,
            scanned=True
        )
        
    except Exception as e:
        return render_template('index.html', error=f"Scanning failed due to runtime anomaly: {str(e)}")

# 4. Boot execution engine
if __name__ == '__main__':
    app.run(debug=True, port=5000)