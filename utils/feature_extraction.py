import re
from urllib.parse import urlparse

def extract_features(url):
    """
    Parses a raw text URL and extracts 6 specific numeric features.
    Returns a list of 0s and 1s.
    """
    features = []
    
    # Ensure the URL has a scheme (http/https) for proper parsing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    # 1. URL Length Check
    # Phishing URLs are often long to pack in fake brand names or subdomains.
    features.append(1 if len(url) > 54 else 0)
    
    # 2. Number of Dots Check
    # Attackers stack subdomains (e.g., login.paypal.com.update.net)
    features.append(1 if url.count('.') > 3 else 0)
    
    # 3. Protocol Security Check (HTTPS vs HTTP)
    # 0 means safe (HTTPS), 1 means suspicious (HTTP)
    features.append(0 if url.startswith('https') else 1)
    
    # 4. Check for Bare IP Address usage
    # Legitimate businesses use domains, scammers often use public IPs directly.
    domain = urlparse(url).netloc
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    features.append(1 if ip_pattern.match(domain) else 0)
    
    # 5. Suspicious Text Keywords Check
    # Looks for words common in credential harvesting scams.
    suspicious_words = ['login', 'verify', 'secure', 'account', 'update', 'banking', 'paypal']
    features.append(1 if any(word in url.lower() for word in suspicious_words) else 0)
    
    # 6. URL Shortening Services Check
    # Attackers hide scary links using free shorteners like bit.ly
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd']
    features.append(1 if any(s in domain.lower() for s in shorteners) else 0)
    
    return features