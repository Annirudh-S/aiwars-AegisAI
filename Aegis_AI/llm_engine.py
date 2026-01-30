import os
import google.generativeai as genai
import json
import re
from urllib.parse import urlparse
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.calibration import CalibratedClassifierCV
import math

class CalibratedPhishingDetector:
    def __init__(self):
        self.api_key = self._load_api_key()
        self.model = None
        self.tfidf = None
        self.scaler = None
        self.rf_model = None
        self.gb_model = None
        
        # Calibration parameters (TUNABLE)
        self.sensitivity = 0.7  # 0.0 = fewer false positives, 1.0 = fewer false negatives
        self.confidence_floor = 0.15  # Minimum confidence to avoid extreme predictions
        self.confidence_ceiling = 0.95  # Maximum confidence to avoid overconfidence
        
        self._train_models()
        
        if self.api_key:
            try:
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel('gemini-1.5-flash')
            except:
                pass

    def _load_api_key(self):
        try:
            if os.path.exists('api_key.txt'):
                with open('api_key.txt', 'r') as f:
                    return f.read().strip()
        except:
            pass
        return None

    def _train_models(self):
        """Train calibrated ensemble ML models"""
        training_data = [
            # Phishing (1)
            ("PayPal Support <security@paypal-verify.com>", "Urgent: Account Suspended", "Your account has been locked due to suspicious activity. Click here to verify your identity immediately.", 1),
            ("Amazon Security <no-reply@amazon-security.net>", "Action Required: Payment Failed", "Your recent order cannot be processed. Update your payment method within 24 hours.", 1),
            ("Microsoft Account <account-security@outlook-verify.com>", "Security Alert: Unusual Sign-in", "We detected an unusual sign-in attempt. Verify your identity now to prevent account closure.", 1),
            ("IRS Notice <notices@irs-refund.com>", "Tax Refund Pending", "You have a pending tax refund of $2,847. Click here to claim your refund before it expires.", 1),
            ("CEO <ceo@gmail.com>", "Urgent Wire Transfer", "I'm in a meeting and need you to process this wire transfer immediately. See attached invoice.", 1),
            ("IT Support <support@company-it.net>", "Password Expiration Notice", "Your password will expire in 2 hours. Reset it now to maintain access to company systems.", 1),
            ("Bank Alert <alerts@secure-banking.com>", "Suspicious Transaction Detected", "We've detected unusual activity on your account. Confirm these transactions immediately.", 1),
            ("Netflix <billing@netflix-update.com>", "Payment Declined", "Your Netflix subscription will be cancelled unless you update your billing information today.", 1),
            ("Apple ID <noreply@apple-id-support.com>", "Verify Your Apple ID", "Your Apple ID has been locked for security reasons. Verify your identity to unlock.", 1),
            ("Google Security <security-noreply@google-accounts.net>", "New Device Sign-in", "A new device signed into your account from an unusual location. Secure your account now.", 1),
            ("HR Department <hr@gmail.com>", "Important: Review Attached Document", "Please review the attached employee handbook update and confirm receipt by end of day.", 1),
            ("Support Team <support@yahoo.com>", "Account Verification Required", "We need to verify your account information. Click the link below to complete verification.", 1),
            ("Wells Fargo <security@wellsfargo-alerts.com>", "Fraud Alert", "We've detected fraudulent charges on your account. Call us immediately at the number below.", 1),
            ("Facebook Security <security@fb-verify.net>", "Unusual Login Activity", "Someone tried to access your Facebook account. Secure your account now.", 1),
            
            # Legitimate (0)
            ("Amazon.com <shipment-tracking@amazon.com>", "Your package has shipped", "Your order #123-4567890-1234567 has been shipped and will arrive by Friday, January 31.", 0),
            ("GitHub <notifications@github.com>", "New pull request on your repository", "User @developer opened a pull request on repository/project. Review the changes when you have time.", 0),
            ("LinkedIn <messages@linkedin.com>", "You have 3 new connection requests", "John Smith, Jane Doe, and 1 other person want to connect with you on LinkedIn.", 0),
            ("Google Calendar <calendar-notification@google.com>", "Reminder: Team Meeting at 2 PM", "Your meeting 'Weekly Team Sync' starts in 15 minutes. Join via Google Meet.", 0),
            ("Slack <notifications@slack.com>", "New message in #engineering", "Sarah posted in #engineering: 'The deployment is complete and all systems are operational.'", 0),
            ("Stripe <receipts@stripe.com>", "Receipt for your payment", "Thank you for your payment of $49.99 to Example SaaS Inc. Receipt #inv_1234567890.", 0),
            ("Zoom <no-reply@zoom.us>", "Meeting invitation from John Smith", "John Smith has invited you to a scheduled Zoom meeting. Topic: Project Review. Time: Jan 30, 2026 3:00 PM.", 0),
            ("Dropbox <no-reply@dropbox.com>", "New file shared with you", "Alice shared 'Q4_Report.pdf' with you in the Marketing folder. View file in Dropbox.", 0),
            ("Twitter <notify@twitter.com>", "Your tweet got 50 likes", "Your recent tweet about AI development received 50 likes and 12 retweets.", 0),
            ("Spotify <no-reply@spotify.com>", "Your Discover Weekly is ready", "We've created a new playlist just for you with 30 songs based on your listening history.", 0),
            ("Adobe <message@adobe.com>", "Your Creative Cloud subscription", "Your Adobe Creative Cloud subscription will renew on February 15, 2026 for $54.99/month.", 0),
            ("Stack Overflow <do-not-reply@stackoverflow.email>", "New answer to your question", "User @expert answered your question about Python async programming. Check out their response.", 0),
            ("Atlassian <notifications@atlassian.com>", "JIRA ticket assigned to you", "Ticket PROJ-123 'Fix login bug' has been assigned to you. Due date: February 5, 2026.", 0),
            ("PayPal <service@paypal.com>", "Receipt for your payment", "You sent $25.00 USD to John Doe. Transaction ID: 1AB23456CD789012E.", 0),
        ]
        
        X_features = []
        y_labels = []
        texts = []
        
        for sender, subject, snippet, label in training_data:
            features = self._extract_advanced_features(sender, subject, snippet)
            X_features.append(features)
            y_labels.append(label)
            texts.append(f"{subject} {snippet}")
        
        # Train TF-IDF
        self.tfidf = TfidfVectorizer(max_features=50, stop_words='english', ngram_range=(1, 2))
        X_tfidf = self.tfidf.fit_transform(texts).toarray()
        
        # Combine features
        X_combined = np.hstack([np.array(X_features), X_tfidf])
        
        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X_combined)
        
        # Train with probability calibration
        rf_base = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
        gb_base = GradientBoostingClassifier(n_estimators=100, max_depth=5, learning_rate=0.1, random_state=42)
        
        # Use CalibratedClassifierCV for better probability estimates
        self.rf_model = CalibratedClassifierCV(rf_base, method='isotonic', cv=3)
        self.gb_model = CalibratedClassifierCV(gb_base, method='isotonic', cv=3)
        
        self.rf_model.fit(X_scaled, y_labels)
        self.gb_model.fit(X_scaled, y_labels)

    def _extract_advanced_features(self, sender, subject, snippet):
        """Extract 20+ engineered features"""
        features = []
        text = (subject + " " + snippet).lower()
        
        # 1-4: Language intensity features
        urgency_words = ['urgent', 'immediate', 'asap', 'now', 'expires', 'limited', 'final']
        fear_words = ['suspended', 'locked', 'unauthorized', 'breach', 'alert', 'compromised']
        credential_words = ['password', 'verify', 'confirm', 'login', 'account', 'identity']
        financial_words = ['payment', 'invoice', 'wire', 'refund', 'billing', 'card']
        
        features.append(sum(1 for w in urgency_words if w in text) / max(len(text.split()), 1))
        features.append(sum(1 for w in fear_words if w in text) / max(len(text.split()), 1))
        features.append(sum(1 for w in credential_words if w in text) / max(len(text.split()), 1))
        features.append(sum(1 for w in financial_words if w in text) / max(len(text.split()), 1))
        
        # 5-7: Sender analysis
        sender_lower = sender.lower()
        domain_match = re.search(r'@([a-zA-Z0-9.-]+)', sender)
        domain = domain_match.group(1) if domain_match else ""
        
        public_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
        features.append(1.0 if any(pd in domain for pd in public_domains) else 0.0)
        
        official_keywords = ['support', 'security', 'admin', 'billing', 'service']
        features.append(1.0 if any(kw in sender_lower for kw in official_keywords) else 0.0)
        
        features.append(domain.count('-') + domain.count('0') + domain.count('1'))
        
        # 8-10: URL analysis
        url_shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co']
        features.append(1.0 if any(short in text for short in url_shorteners) else 0.0)
        
        click_phrases = ['click here', 'click link', 'verify here']
        features.append(1.0 if any(phrase in text for phrase in click_phrases) else 0.0)
        
        url_count = len(re.findall(r'http[s]?://', text))
        features.append(min(url_count / 5.0, 1.0))
        
        # 11-13: Structural features
        features.append(1.0 if subject.isupper() and len(subject) > 10 else 0.0)
        features.append(text.count('!') / max(len(text), 1))
        
        generic_greetings = ['dear customer', 'dear user', 'valued member']
        features.append(1.0 if any(g in text for g in generic_greetings) else 0.0)
        
        # 14-16: Text statistics
        features.append(len(text.split()))
        features.append(len(text))
        features.append(len(subject.split()))
        
        # 17-20: Advanced linguistic features
        caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
        features.append(caps_ratio)
        
        punct_count = sum(1 for c in text if c in '!?.')
        features.append(punct_count / max(len(text), 1))
        
        num_count = sum(1 for c in text if c.isdigit())
        features.append(num_count / max(len(text), 1))
        
        if len(text) > 0:
            char_freq = {}
            for c in text:
                char_freq[c] = char_freq.get(c, 0) + 1
            entropy = -sum((freq/len(text)) * math.log2(freq/len(text)) for freq in char_freq.values())
            features.append(entropy / 10.0)
        else:
            features.append(0.0)
        
        return features

    def _calibrate_probability(self, raw_prob):
        """Apply sigmoid calibration to raw probability"""
        # Platt scaling-inspired transformation
        # Maps raw probabilities to a more balanced distribution
        
        # Apply sensitivity adjustment
        adjusted = raw_prob + (self.sensitivity - 0.5) * 0.2
        
        # Clip to valid range
        adjusted = max(self.confidence_floor, min(self.confidence_ceiling, adjusted))
        
        # Apply sigmoid smoothing to reduce extreme predictions
        beta = 2.0  # Controls smoothing strength
        calibrated = 1 / (1 + np.exp(-beta * (adjusted - 0.5)))
        
        # Rescale to [confidence_floor, confidence_ceiling]
        calibrated = self.confidence_floor + (self.confidence_ceiling - self.confidence_floor) * calibrated
        
        return calibrated

    def analyze_email(self, sender, subject, snippet):
        """
        Calibrated ML-based phishing detection
        Returns: (score [0-100], explanation [str], risk_level [str])
        """
        try:
            # Extract features
            features = self._extract_advanced_features(sender, subject, snippet)
            text = f"{subject} {snippet}"
            
            # TF-IDF features
            tfidf_features = self.tfidf.transform([text]).toarray()
            
            # Combine and scale
            X_combined = np.hstack([np.array(features).reshape(1, -1), tfidf_features])
            X_scaled = self.scaler.transform(X_combined)
            
            # Ensemble prediction with calibrated probabilities
            rf_prob = self.rf_model.predict_proba(X_scaled)[0][1]
            gb_prob = self.gb_model.predict_proba(X_scaled)[0][1]
            
            # Weighted ensemble: 60% GB, 40% RF
            ml_score = 0.6 * gb_prob + 0.4 * rf_prob
            
            # Apply calibration
            calibrated_score = self._calibrate_probability(ml_score)
            
            # Heuristic adjustments for edge cases
            sender_lower = sender.lower()
            text_lower = text.lower()
            
            # Critical boost: Official name on public domain
            public_domains = ['gmail.com', 'yahoo.com', 'hotmail.com']
            official_keywords = ['paypal', 'amazon', 'microsoft', 'apple', 'bank', 'irs', 'facebook']
            if any(pd in sender_lower for pd in public_domains) and any(kw in sender_lower for kw in official_keywords):
                calibrated_score = min(0.95, calibrated_score + 0.25)
            
            # Legitimate boost: Known safe domains
            safe_domains = ['@amazon.com', '@github.com', '@google.com', '@microsoft.com', '@paypal.com', '@stripe.com']
            if any(sd in sender_lower for sd in safe_domains):
                calibrated_score = max(0.05, calibrated_score - 0.3)
            
            final_score = calibrated_score
            
            # User-defined thresholds: 0-50% = Low, 50-75% = High, 75-100% = Threat
            threat_threshold = 0.75
            high_threshold = 0.50
            
            # Determine risk level
            if final_score >= threat_threshold:
                risk_level = "Critical"
                explanation = "Threat detected: Multiple strong phishing indicators identified"
            elif final_score >= high_threshold:
                risk_level = "High"
                explanation = "High risk: Several suspicious patterns detected"
            else:
                risk_level = "Low"
                explanation = "Low risk: Appears legitimate"

            
            # Convert to 0-100 scale
            score_100 = int(final_score * 100)
            
            return score_100, explanation, risk_level
            
        except Exception as e:
            print(f"Algorithm Error: {e}")
            return 0, f"Analysis Error: {str(e)}", "Low"

llm_engine = CalibratedPhishingDetector()
