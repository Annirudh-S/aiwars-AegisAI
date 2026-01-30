import random
import os
import csv
from datetime import datetime

class LoginThreatEngine:
    def __init__(self, data_path='data/UNSW_NB15_training-set.csv'):
        self.data_path = data_path
        self.is_trained = False
        
        # Mapping generic dataset categories to our security dashboard categories
        self.category_mapping = {
            'Normal': 'Normal',
            'Generic': 'Reconnaissance', # Map Generic network scans to Recon
            'Exploits': 'Brute Force',   # Map Exploits to Brute Force for demo
            'Fuzzers': 'DDoS',
            'DoS': 'DDoS',
            'Reconnaissance': 'Reconnaissance'
        }

    def train(self):
        print("Training Login Threat Detection Model (Rule-Based Fallback)...")
        # In this fallback version, we don't actually train a model because sklearn is missing.
        # We will use heuristic rules in predict_threat.
        self.is_trained = True
        print("Login Threat Model (Fallback) Ready.")
            
    def predict_threat(self, log_entry):
        """
        Analyzes a single log entry using heuristics.
        log_entry: dict with keys 'proto', 'service', 'state', 'ip', etc.
        """
        if not self.is_trained:
            return "Unknown", 0.0

        service = log_entry.get('service', '').lower()
        state = log_entry.get('state', '').upper()
        proto = log_entry.get('proto', '').lower()
        
        # Simple Heuristics to mimic the ML model
        category = 'Normal'
        confidence = 0.1
        
        if state == 'INT' or state == 'REQ':
            # Incomplete/Requested states often imply scanning or DoS
            if proto == 'udp':
                category = 'DDoS'
                confidence = 0.85
            else:
                category = 'Reconnaissance'
                confidence = 0.70
                
        if service in ['ssh', 'ftp', 'rdp'] and state == 'FIN':
             # Successful or attempted login on sensitive ports
             # Randomly flag as brute force for demo purposes if we want to show threats
             pass

        return category, confidence

    def process_real_logs(self, raw_logs):
        """
        Processes real logs from login_attempts.json through the threat detection logic.
        """
        processed_logs = []
        for log in raw_logs:
            # Analyze using our heuristics
            category, confidence = self.predict_threat(log)
            
            # If it's a known failure from our web app, prioritize that categorization
            if log.get('status') == 'Failure':
                category = 'Brute Force'
                # Score increases with number of attempts from this IP
                risk_score = min(98, 45 + (log.get('attempts', 1) * 8))
            else:
                # Use predicted category or normal
                risk_score = int(confidence * 100) if category != 'Normal' else random.randint(1, 10)

            processed_logs.append({
                "timestamp": log.get('time_only') or log.get('timestamp', '').split(' ')[-1],
                "ip": log.get('ip', '0.0.0.0'),
                "proto": log.get('proto', 'http'),
                "service": log.get('service', 'Web Login'),
                "state": log.get('state', 'FIN' if log.get('status') == 'Success' else 'REQ'),
                "category": category,
                "risk_score": risk_score
            })
        return processed_logs

    def generate_mock_login_traffic(self, count=5):
        """
        Generates simulated live traffic logs for the dashboard.
        """
        logs = []
        for _ in range(count):
            # Introduce some bias towards threats for demonstration
            is_threat = random.random() < 0.4 # Slightly more threats
            
            if is_threat:
                proto = random.choice(['tcp', 'udp'])
                service = random.choice(['ssh', 'ftp', 'rdp', 'vnc']) # More vulnerable services
                state = random.choice(['INT', 'REQ', 'RST']) 
            else:
                proto = 'tcp'
                service = 'http'
                state = 'FIN'

            log_entry = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "ip": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}", # Use external IPs for cooler effect
                "proto": proto,
                "service": service,
                "state": state
            }
            
            # Predict
            category, confidence = self.predict_threat(log_entry)
            
            # Significant boost to threat scores to make them "stand out"
            if is_threat:
                category = random.choice(['Brute Force', 'Ransomware Entry', 'DDoS Attack'])
                risk_score = random.randint(85, 99) # Very high scores
            else:
                category = 'Normal'
                risk_score = random.randint(1, 10)

            logs.append({
                **log_entry,
                "category": category,
                "risk_score": risk_score
            })
            
        return logs

# Singleton
login_engine = LoginThreatEngine()
