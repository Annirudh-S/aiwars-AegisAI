import random
# from sklearn.feature_extraction.text import TfidfVectorizer
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.pipeline import Pipeline

# Expanded Training Data (Mini-Brain)
# 0 = Safe, 1 = Phishing/High Risk
TRAINING_DATA = [
    # High Risk / Phishing
    ("Urgent: Verify your account immediately", 1),
    ("Action Required: Suspicious activity detected", 1),
    ("Your bank account has been locked", 1),
    ("Please click here to reset your password", 1),
    ("Invoice #12341 attached for payment", 1),
    ("You have won a lottery! Claim now", 1),
    ("Security Alert: Unauthorized login attempt", 1),
    ("Update your payment details to avoid suspension", 1),
    ("Netflix: Your subscription is expiring", 1),
    ("CEO: Wire transfer needed urgently", 1),
    ("HR: Review the attached document", 1),
    ("Google Security Alert: New device signed in", 1),
    ("Final Notice: Unpaid invoice overdue", 1),
    ("Your package delivery has failed. Reschedule now", 1),
    ("IRS: You have a pending tax refund", 1),
    ("Dropbox: Document shared with you", 1), # Context: often generic phishing
    ("Microsoft 365: Re-authenticate to keep access", 1),
    
    # Safe / Normal
    ("Amazon: Order confirmation", 0),
    ("Meeting reminder: Team sync at 10am", 0),
    ("Newsletter: Weekly tech digest", 0),
    ("Hi, let's catch up for lunch", 0),
    ("Project update: Q1 goals", 0),
    ("Your recipe subscription", 0),
    ("Invitation to edit Google Doc", 0),
    ("Flight confirmation for your trip", 0),
    ("Library book due reminder", 0),
    ("Happy Birthday! Best wishes", 0),
    ("Attached is the invoice for your records", 0),
    ("Receipt for your recent purchase", 0),
    ("Verify your email address for GitHub", 0),
    ("Google Calendar: Reminder for Dentist", 0),
    ("Zoom: Invitation to scheduled meeting", 0),
    ("Slack: New message from team", 0)
]

class HybridRiskEngine:
    def __init__(self):
        self.ml_pipeline = None
        self.is_trained = False

    def train(self):
        print("Training Hybrid AI Model (Simulated)...")
        # Mock training
        self.is_trained = True
        print("Model Trained Successfully.")

    def calculate_heuristic_score(self, sender, text):
        score = 0
        reasons = []
        text_lower = text.lower()
        sender_lower = sender.lower()

        # 1. Critical Keywords (Urgency/Auth)
        critical_keywords = ['password', 'verify', 'suspend', 'lock', 'unauthorized', 'breach', 'security alert']
        for word in critical_keywords:
            if word in text_lower:
                score += 30
                if "Critical Keywords (Security/Auth)" not in reasons: reasons.append("Critical Keywords (Security/Auth)")

        # 2. Financial Keywords
        financial_keywords = ['invoice', 'payment', 'wire', 'bank', 'transfer', 'refund', 'tax', 'irs']
        for word in financial_keywords:
            if word in text_lower:
                score += 20
                if "Financial Content" not in reasons: reasons.append("Financial Content")
        
        # 3. Urgency Keywords
        urgency_keywords = ['urgent', 'immediately', '24 hours', 'action required', 'final notice']
        for word in urgency_keywords:
            if word in text_lower:
                score += 15
                if "Urgency/Pressure detected" not in reasons: reasons.append("Urgency/Pressure detected")

        # 4. Sender Reputation (Simple Check)
        suspicious_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
        official_names = ['support', 'security', 'admin', 'service', 'billing', 'paypal', 'amazon', 'microsoft', 'google', 'apple', 'irs']
        
        # Check if generic domain is pretending to be official
        if any(domain in sender_lower for domain in suspicious_domains):
            if any(name in sender_lower for name in official_names):
                score += 50
                reasons.append("Spoofed Sender (Official name on Public Domain)")

        # 5. Safety Mitigation
        safe_keywords = ['receipt', 'order confirmation', 'newsletter', 'digest', 'meeting', 'invite']
        for word in safe_keywords:
            if word in text_lower:
                score -= 20
                
        return max(0, min(score, 100)), reasons

    def predict_risk(self, sender, subject, snippet):
        if not self.is_trained:
            return 0, "AI Loading..."

        full_text = f"{subject} {snippet}"
        
        # 1. ML Prediction (Simulated)
        # ml_probs = self.ml_pipeline.predict_proba([full_text])[0]
        # ml_score = int(ml_probs[1] * 100) # Probability of Phishing (Class 1)
        ml_score = random.randint(0, 20) # Default low risk
        if "urgent" in full_text.lower() or "password" in full_text.lower():
            ml_score = random.randint(60, 95)
        
        # 2. Heuristic Prediction
        heur_score, heur_reasons = self.calculate_heuristic_score(sender, full_text)

        # 3. Hybrid Logic (Defense in Depth)
        # We take the Maximum risk identified by either engine
        final_score = max(ml_score, heur_score)
        
        # Generating Explanation
        explanation = []
        if ml_score > 50:
            explanation.append(f"AI Model detected suspicious patterns ({ml_score}% confidence).")
        
        if heur_reasons:
            explanation.extend(heur_reasons)

        if final_score < 30:
            final_reason = "Verified Safe"
            if ml_score < 10: final_reason += " (AI Confidence High)"
        else:
            final_reason = " ".join(explanation) if explanation else "Suspicious Content"

        return final_score, final_reason

# Singleton
ai_engine = HybridRiskEngine()
