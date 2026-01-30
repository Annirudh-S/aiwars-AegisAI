import os
import random
import json
import base64
import re
from datetime import datetime
from email.mime.text import MIMEText
import google.generativeai as genai
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Configuration
TARGET_EMAIL = "defenderaitest@gmail.com"
SCOPES = ['https://www.googleapis.com/auth/gmail.send']
API_KEY_FILE = 'api_key.txt'
TOKEN_FILE = 'attacker_token.json'
CREDENTIALS_FILE = 'credentials.json'

class AttackerAI:
    def __init__(self):
        self.api_key = self._load_api_key()
        if self.api_key:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel('gemini-1.5-flash')
        else:
            print("Warning: No API key found. LLM generation will fail.")
            self.model = None

    def _load_api_key(self):
        if os.path.exists(API_KEY_FILE):
            with open(API_KEY_FILE, 'r') as f:
                return f.read().strip()
        return None

    def get_gmail_service(self):
        creds = None
        if os.path.exists(TOKEN_FILE):
            creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not os.path.exists(CREDENTIALS_FILE):
                    raise FileNotFoundError(f"{CREDENTIALS_FILE} not found. Please provide it for OAuth.")
                flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
                creds = flow.run_local_server(port=0)
            
            with open(TOKEN_FILE, 'w') as token:
                token.write(creds.to_json())
        
        return build('gmail', 'v1', credentials=creds)

    def generate_email_content(self, is_phishing=True):
        if not self.model:
            return "Default Subject", "Default Body"

        if is_phishing:
            prompt = (
                "Generate a highly convincing phishing email subject and body. "
                "The email should pretend to be from a well-known service (like Amazon, PayPal, or Microsoft) "
                "or a company executive. It should create a sense of urgency, mention a security problem "
                "or a pending payment, and include a call to action (like 'click here to verify'). "
                "Format as JSON: {\"subject\": \"...\", \"body\": \"...\"}"
            )
        else:
            prompt = (
                "Generate a normal, legitimate business or personal email subject and body. "
                "It could be a meeting invitation, a project update, or a friendly check-in. "
                "Format as JSON: {\"subject\": \"...\", \"body\": \"...\"}"
            )

        try:
            response = self.model.generate_content(prompt)
            # Find JSON in response
            match = re.search(r'\{.*\}', response.text, re.DOTALL)
            if match:
                data = json.loads(match.group(0))
                return data.get('subject', 'No Subject'), data.get('body', 'No Body')
        except Exception as e:
            print(f"LLM Error: {e}")
        
        return ("Alert: Account Update", "Please check your account for recent changes.") if is_phishing else ("Lunch tomorrow?", "Hey, want to grab lunch tomorrow?")

    def send_email(self, service, subject, body):
        try:
            message = MIMEText(body)
            message['to'] = TARGET_EMAIL
            message['from'] = 'me'
            message['subject'] = subject
            
            raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
            
            sent_message = service.users().messages().send(
                userId='me',
                body={'raw': raw_message}
            ).execute()
            
            print(f"Message sent successfully! ID: {sent_message['id']}")
            return sent_message
        except HttpError as error:
            print(f"An error occurred: {error}")
            return None

if __name__ == "__main__":
    attacker = AttackerAI()
    
    # Randomly choose phishing or legit
    is_phishing = random.random() < 0.5
    type_str = "PHISHING" if is_phishing else "LEGITIMATE"
    
    print(f"--- Launching Attacker AI ---")
    print(f"Mode: {type_str}")
    
    print("Generating content...")
    subject, body = attacker.generate_email_content(is_phishing=is_phishing)
    print(f"Subject: {subject}")
    print(f"Body: {body[:100]}...")
    
    try:
        print("Authenticating with Gmail...")
        service = attacker.get_gmail_service()
        
        print(f"Sending to {TARGET_EMAIL}...")
        attacker.send_email(service, subject, body)
        
    except Exception as e:
        print(f"Execution Error: {e}")
