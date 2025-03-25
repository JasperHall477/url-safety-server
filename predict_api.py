from flask import Flask, request, jsonify
import joblib
from sklearn.base import BaseEstimator, TransformerMixin
from urllib.parse import urlparse

app = Flask(__name__)

class URLFeatureExtractor(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self
    
    def transform(self, X):
        features = []
        for url in X:
            parsed = urlparse(url)
            domain = parsed.netloc or url
            subdomains = len(domain.split('.')) - 2
            has_phishing_keyword = any(kw in url.lower() for kw in ['login', 'phishing', 'secure', 'account', 'verify'])
            url_length = len(url)
            special_chars = sum(1 for c in url if c in '-_?.&=')
            tld = domain.split('.')[-1] if '.' in domain else ''
            is_suspicious_tld = tld in ['xyz', 'top', 'info']
            features.append(
                f"{domain} subdomains:{subdomains} phishing:{int(has_phishing_keyword)} "
                f"len:{url_length} specials:{special_chars} susp_tld:{int(is_suspicious_tld)}"
            )
        return features

model = joblib.load('url_safety_model.pkl')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    proba = model.predict_proba([url])[0]
    threshold = 0.4
    prediction = 1 if proba[1] > threshold else 0
    return jsonify({'phishing': 'Unsafe' if prediction else 'Safe'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)