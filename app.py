from flask import Flask, render_template, request, jsonify
import pandas as pd
import numpy as np
import pickle
import re
import warnings
from urllib.parse import urlparse
import tldextract
import os

warnings.filterwarnings('ignore')

app = Flask(__name__)

class EnhancedHomoglyphDetector:
    def __init__(self):
        self.homoglyph_map = {
            'a': ['а', 'ɑ', 'а', '⍺', 'а'],
            'e': ['е', 'є', 'ҽ', 'е'],
            'i': ['і', 'і', 'ⅰ', 'і', 'і'],
            'o': ['о', 'ο', 'о', 'օ', 'о'],
            'c': ['с', 'ϲ', 'с', 'ⅽ'],
            'p': ['р', 'ρ', 'р', 'ⲣ'],
            'x': ['х', 'х', 'ⅹ', 'ⲭ'],
            'y': ['у', 'ү', 'у', 'у'],
            's': ['ѕ', 'ѕ', 'ꜱ'],
            'm': ['м', 'м', 'ⅿ'],
            'n': ['п', 'п', 'ո'],
            '0': ['O', 'Ο', 'О', '₀'],
            '1': ['l', 'I', 'і', 'Ⅰ'],
        }
        
        self.homoglyph_detection_map = {}
        for original, variants in self.homoglyph_map.items():
            for variant in variants:
                self.homoglyph_detection_map[variant] = original
        
        self.multi_char_homoglyphs = {
            'rn': 'm', 'vv': 'w', 'cl': 'd', 'ii': 'u', 'nn': 'm', 'rr': 'n',
        }
    
    def analyze_url(self, url):
        homoglyph_count = 0
        suspicious_chars = []
        normalized_chars = []
        
        for char in url:
            if char in self.homoglyph_detection_map:
                homoglyph_count += 1
                suspicious_chars.append(char)
                normalized_chars.append(self.homoglyph_detection_map[char])
            else:
                normalized_chars.append(char)
        
        normalized_url = ''.join(normalized_chars)
        
        multi_char_detected = []
        url_lower = url.lower()
        
        for pattern, replacement in self.multi_char_homoglyphs.items():
            if pattern in url_lower:
                homoglyph_count += 2
                multi_char_detected.append(f"{pattern}->{replacement}")
                normalized_url = normalized_url.replace(pattern, replacement)
        
        homoglyph_patterns = [
            (r'раypаl', 'paypal'), (r'gооgle', 'google'), (r'аррle', 'apple'),
            (r'micrоsоft', 'microsoft'), (r'googIe', 'google'), (r'paypaI', 'paypal'),
        ]
        
        for pattern, normal in homoglyph_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                homoglyph_count += 2
                multi_char_detected.append(f"pattern->{normal}")
        
        if 'xn--' in url_lower:
            homoglyph_count += 3
            
        if '%' in url and len(url) > 30:
            encoded_segments = re.findall(r'%[0-9a-fA-F]{2}', url)
            if len(encoded_segments) > 2:
                homoglyph_count += 2
                
        if '@' in url:
            homoglyph_count += 3
        
        risk_score = min((homoglyph_count / max(len(url), 1)) * 100, 100)
        
        return {
            'homoglyph_count': homoglyph_count,
            'suspicious_chars': suspicious_chars,
            'multi_char_homoglyphs': multi_char_detected,
            'normalized_url': normalized_url,
            'homoglyph_risk_score': risk_score,
            'is_suspicious_homoglyph': risk_score > 5,
        }

class ImprovedURLFeatureExtractor:
    def __init__(self):
        self.sensitive_keywords = ['login', 'signin', 'verify', 'account', 'security', 'bank', 'pay', 'password', 'update', 'confirm']
        self.brand_names = ['paypal', 'google', 'apple', 'microsoft', 'amazon', 'facebook', 'github', 'netflix', 'twitter', 'instagram']
        
        self.legitimate_domains = {
            'microsoft.com', 'microsoftonline.com', 'live.com', 'outlook.com', 'office.com',
            'azure.com', 'windows.net', 'msft.net', 'msn.com', 'sharepoint.com',
            'google.com', 'gmail.com', 'youtube.com', 'googleapis.com', 'gstatic.com',
            'googleusercontent.com', 'googletagmanager.com', 'google-analytics.com',
            'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.jp',
            'aws.amazon.com', 'amazonaws.com', 'apple.com', 'icloud.com',
            'github.com', 'githubusercontent.com', 'dropbox.com', 'slack.com',
            'stackoverflow.com', 'cloudflare.com', 'paypal.com', 'facebook.com',
        }
        
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club', '.online', '.site', '.info', '.biz']
        self.legitimate_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.io', '.co.uk', '.de', '.fr', '.jp', '.ca', '.au']
    
    def extract_all_features(self, url):
        try:
            url_lower = url.lower()
            has_https = url_lower.startswith('https://')
            
            extracted = tldextract.extract(url)
            domain = extracted.domain
            subdomain = extracted.subdomain
            suffix = extracted.suffix
            full_domain = f"{domain}.{suffix}" if domain and suffix else ""
            
            is_legitimate_domain = full_domain in self.legitimate_domains
            has_legitimate_tld = any(suffix.endswith(tld) for tld in self.legitimate_tlds)
            has_suspicious_tld = any(suffix.endswith(tld) for tld in self.suspicious_tlds)
            
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            path = parsed.path or ""
            query = parsed.query or ""
            
            has_embedded_brand = 0
            brand_in_subdomain = 0
            
            for brand in self.brand_names:
                if brand in subdomain.lower() and domain != brand:
                    has_embedded_brand = 1
                    brand_in_subdomain = 1
                elif brand in domain and domain != brand:
                    has_embedded_brand = 1
                elif domain == brand and has_suspicious_tld:
                    has_embedded_brand = 1
            
            if is_legitimate_domain:
                has_embedded_brand = 0
                brand_in_subdomain = 0
            
            subdomain_level = subdomain.count('.') + 1 if subdomain else 0
            
            homoglyph_detector = EnhancedHomoglyphDetector()
            homoglyph_analysis = homoglyph_detector.analyze_url(url)
            homoglyph_score = homoglyph_analysis['homoglyph_count']
            
            if is_legitimate_domain:
                pct_ext_hyperlinks = 0.1
                pct_null_redirects_rt = 1
                frequent_mismatch = 0
                pct_ext_resources = 0.2
            elif has_embedded_brand or homoglyph_score > 2:
                pct_ext_hyperlinks = 0.85
                pct_null_redirects_rt = -1
                frequent_mismatch = 1
                pct_ext_resources = 0.9
            else:
                pct_ext_hyperlinks = 0.1
                pct_null_redirects_rt = 1
                frequent_mismatch = 0
                pct_ext_resources = 0.2
            
            has_at_obfuscation = 1 if '@' in url and not is_legitimate_domain else 0
            excessive_encoding = 1 if url.count('%') > 3 and len(url) > 50 else 0
            
            features = {
                'NumDots': url.count('.'),
                'SubdomainLevel': subdomain_level,
                'PathLevel': path.count('/'),
                'UrlLength': len(url),
                'NumDash': url.count('-'),
                'NumDashInHostname': hostname.count('-'),
                'AtSymbol': 1 if '@' in url else 0,
                'TildeSymbol': 1 if '~' in url else 0,
                'NumUnderscore': url.count('_'),
                'NumPercent': url.count('%'),
                'NumQueryComponents': len(query.split('&')) if query else 0,
                'NumAmpersand': url.count('&'),
                'NumHash': url.count('#'),
                'NumNumericChars': sum(c.isdigit() for c in url),
                'NoHttps': 0 if has_https else 1,
                'RandomString': 1 if re.search(r'[a-z0-9]{10,}', hostname) else 0,
                'IpAddress': 1 if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url) else 0,
                'DomainInSubdomains': brand_in_subdomain,
                'DomainInPaths': 1 if any(brand in path.lower() for brand in self.brand_names) else 0,
                'HttpsInHostname': 1 if 'https' in hostname else 0,
                'HostnameLength': len(hostname),
                'PathLength': len(path),
                'QueryLength': len(query),
                'DoubleSlashInPath': 1 if '//' in path else 0,
                'NumSensitiveWords': sum(1 for word in self.sensitive_keywords if word in url_lower),
                'EmbeddedBrandName': has_embedded_brand,
                'PctExtHyperlinks': pct_ext_hyperlinks,
                'PctExtResourceUrls': pct_ext_resources,
                'ExtFavicon': 1 if has_embedded_brand and not is_legitimate_domain else 0,
                'InsecureForms': 1 if not has_https and any(word in url_lower for word in ['login', 'signin', 'password']) else 0,
                'RelativeFormAction': 1 if path and len(path) > 10 else 0,
                'ExtFormAction': 1 if has_embedded_brand and not is_legitimate_domain else 0,
                'AbnormalFormAction': 1 if any(x in url for x in ['javascript:', 'mailto:', 'data:']) else 0,
                'PctNullSelfRedirectHyperlinks': 0.7 if has_embedded_brand and not is_legitimate_domain else 0.1,
                'FrequentDomainNameMismatch': frequent_mismatch,
                'FakeLinkInStatusBar': 0,
                'RightClickDisabled': 0,
                'PopUpWindow': 1 if has_embedded_brand and not is_legitimate_domain else 0,
                'SubmitInfoToEmail': 1 if 'mailto:' in url or 'email' in url_lower else 0,
                'IframeOrFrame': 1 if has_embedded_brand and not is_legitimate_domain else 0,
                'MissingTitle': 0,
                'ImagesOnlyInForm': 0,
                'SubdomainLevelRT': -1 if subdomain_level > 3 else 1 if subdomain_level > 1 else 0,
                'UrlLengthRT': -1 if len(url) > 100 else 1 if len(url) > 50 else 0,
                'PctExtResourceUrlsRT': -1 if has_embedded_brand and not is_legitimate_domain else 1,
                'AbnormalExtFormActionR': 1 if has_embedded_brand and not is_legitimate_domain else -1,
                'ExtMetaScriptLinkRT': -1 if has_embedded_brand and not is_legitimate_domain else 1,
                'PctExtNullSelfRedirectHyperlinksRT': pct_null_redirects_rt,
                'HomoglyphScore': homoglyph_score,
                'IsLegitimateDomain': 1 if is_legitimate_domain else 0,
                'HasSuspiciousTLD': 1 if has_suspicious_tld else 0,
                'HasAtObfuscation': has_at_obfuscation,
                'HasExcessiveEncoding': excessive_encoding,
            }
            
            return features
            
        except Exception as e:
            print(f"Error extracting features: {e}")
            return self.get_default_features()
    
    def get_default_features(self):
        default_features = {key: 0 for key in [
            'NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash', 'NumDashInHostname',
            'AtSymbol', 'TildeSymbol', 'NumUnderscore', 'NumPercent', 'NumQueryComponents', 'NumAmpersand',
            'NumHash', 'NumNumericChars', 'NoHttps', 'RandomString', 'IpAddress', 'DomainInSubdomains',
            'DomainInPaths', 'HttpsInHostname', 'HostnameLength', 'PathLength', 'QueryLength', 'DoubleSlashInPath',
            'NumSensitiveWords', 'EmbeddedBrandName', 'PctExtHyperlinks', 'PctExtResourceUrls', 'ExtFavicon',
            'InsecureForms', 'RelativeFormAction', 'ExtFormAction', 'AbnormalFormAction', 'PctNullSelfRedirectHyperlinks',
            'FrequentDomainNameMismatch', 'FakeLinkInStatusBar', 'RightClickDisabled', 'PopUpWindow', 'SubmitInfoToEmail',
            'IframeOrFrame', 'MissingTitle', 'ImagesOnlyInForm', 'SubdomainLevelRT', 'UrlLengthRT', 'PctExtResourceUrlsRT',
            'AbnormalExtFormActionR', 'ExtMetaScriptLinkRT', 'PctExtNullSelfRedirectHyperlinksRT', 'HomoglyphScore',
            'IsLegitimateDomain', 'HasSuspiciousTLD', 'HasAtObfuscation', 'HasExcessiveEncoding'
        ]}
        return default_features

class PhishingDetector:
    def __init__(self, model_path='phishing_model.pkl'):
        self.models = {}
        self.feature_names = None
        self.feature_extractor = ImprovedURLFeatureExtractor()
        self.homoglyph_detector = EnhancedHomoglyphDetector()
        self.load_model(model_path)
    
    def load_model(self, model_path):
        try:
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)
            self.models = model_data['models']
            self.feature_names = model_data['feature_names']
            print("✅ Model loaded successfully")
        except FileNotFoundError:
            print(f"❌ Model file {model_path} not found")
            self.models = {'ensemble': self.create_fallback_model()}
            self.feature_names = [
                'NumDots', 'SubdomainLevel', 'UrlLength', 'NoHttps', 'EmbeddedBrandName',
                'HomoglyphScore', 'HasAtObfuscation', 'HasSuspiciousTLD'
            ]
    
    def create_fallback_model(self):
        from sklearn.ensemble import RandomForestClassifier
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        X_dummy = np.zeros((10, len(self.feature_names)))
        y_dummy = np.zeros(10)
        model.fit(X_dummy, y_dummy)
        return model
    
    def predict(self, features_dict):
        if not self.models:
            return {'error': 'Model not loaded'}
        
        try:
            features_df = pd.DataFrame([features_dict])
            
            for feature in self.feature_names:
                if feature not in features_df.columns:
                    features_df[feature] = 0
            
            features_df = features_df[self.feature_names]
            
            prediction = self.models['ensemble'].predict(features_df)[0]
            probability = self.models['ensemble'].predict_proba(features_df)[0][1]
            
            return {
                'is_phishing': bool(prediction),
                'probability': float(probability),
                'confidence': 'HIGH' if probability > 0.8 else 'MEDIUM' if probability > 0.6 else 'LOW',
                'verdict': 'PHISHING' if prediction else 'LEGITIMATE'
            }
        except Exception as e:
            print(f"Prediction error: {e}")
            homoglyph_score = features_dict.get('HomoglyphScore', 0)
            has_embedded_brand = features_dict.get('EmbeddedBrandName', 0)
            is_legitimate = features_dict.get('IsLegitimateDomain', 0)
            has_at_obfuscation = features_dict.get('HasAtObfuscation', 0)
            
            if is_legitimate:
                return {
                    'is_phishing': False,
                    'probability': 0.1,
                    'confidence': 'LOW',
                    'verdict': 'LEGITIMATE'
                }
            elif has_at_obfuscation or homoglyph_score > 3 or (has_embedded_brand and not is_legitimate):
                return {
                    'is_phishing': True,
                    'probability': 0.85,
                    'confidence': 'HIGH',
                    'verdict': 'PHISHING'
                }
            else:
                return {
                    'is_phishing': False,
                    'probability': 0.2,
                    'confidence': 'LOW',
                    'verdict': 'LEGITIMATE'
                }
    
    def analyze_url(self, url):
        homoglyph_analysis = self.homoglyph_detector.analyze_url(url)
        features = self.feature_extractor.extract_all_features(url)
        ml_result = self.predict(features)
        
        is_legitimate = features.get('IsLegitimateDomain', 0) == 1
        homoglyph_risk = homoglyph_analysis['homoglyph_risk_score']
        has_at_obfuscation = features.get('HasAtObfuscation', 0) == 1
        
        if is_legitimate:
            final_verdict = "LOW_RISK"
            ml_result['probability'] = min(ml_result['probability'], 0.2)
            ml_result['verdict'] = 'LEGITIMATE'
            ml_result['is_phishing'] = False
        elif has_at_obfuscation:
            final_verdict = "HIGH_RISK"
            ml_result['probability'] = max(ml_result['probability'], 0.9)
            ml_result['verdict'] = 'PHISHING'
            ml_result['is_phishing'] = True
        elif homoglyph_risk > 20 or homoglyph_analysis['homoglyph_count'] > 3:
            final_verdict = "HIGH_RISK"
            ml_result['probability'] = max(ml_result['probability'], 0.8)
            ml_result['verdict'] = 'PHISHING'
            ml_result['is_phishing'] = True
        elif ml_result['is_phishing'] and homoglyph_analysis['is_suspicious_homoglyph']:
            final_verdict = "HIGH_RISK"
        elif ml_result['is_phishing']:
            final_verdict = "MEDIUM_RISK"
        elif homoglyph_analysis['is_suspicious_homoglyph']:
            final_verdict = "MEDIUM_RISK"
            ml_result['probability'] = max(ml_result['probability'], 0.5)
        else:
            final_verdict = "LOW_RISK"
        
        return {
            'url': url,
            'final_verdict': final_verdict,
            'ml_result': ml_result,
            'homoglyph_analysis': homoglyph_analysis,
            'critical_features': {
                'IsLegitimateDomain': features.get('IsLegitimateDomain', 0),
                'EmbeddedBrandName': features.get('EmbeddedBrandName', 0),
                'HasSuspiciousTLD': features.get('HasSuspiciousTLD', 0),
                'HomoglyphScore': features.get('HomoglyphScore', 0),
                'HasAtObfuscation': features.get('HasAtObfuscation', 0),
                'HasExcessiveEncoding': features.get('HasExcessiveEncoding', 0)
            }
        }

# Initialize the detector
detector = PhishingDetector('phishing_model.pkl')

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_url():
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        result = detector.analyze_url(url)
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/batch-analyze', methods=['POST'])
def batch_analyze():
    try:
        data = request.get_json()
        urls = data.get('urls', [])
        
        if not urls:
            return jsonify({'error': 'URLs are required'}), 400
        
        results = []
        for url in urls:
            if url.strip():
                full_url = url if url.startswith(('http://', 'https://')) else 'https://' + url
                result = detector.analyze_url(full_url)
                results.append(result)
        
        return jsonify({'results': results})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)