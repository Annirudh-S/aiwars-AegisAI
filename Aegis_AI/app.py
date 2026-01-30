from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from functools import wraps
from datetime import datetime, timedelta
import random
import os
import base64
import json
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from llm_engine import llm_engine
from login_engine import login_engine
from money_engine import money_engine # Import Login Threat Engine

app = Flask(__name__)
# Use environment variable for the Flask secret key. Replace the placeholder or set FLASK_SECRET_KEY in your environment.
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'PASTE_YOUR_FLASK_SECRET_KEY_HERE')  # Set FLASK_SECRET_KEY env var or replace placeholder
# No explicit training needed for LLM
login_engine.train() # Train Login Threat Model

LOGIN_LOGS_FILE = 'login_attempts.json'

def log_login_attempt(username, status, ip_address):
    """Log login attempts to a JSON file"""
    logs = []
    if os.path.exists(LOGIN_LOGS_FILE):
        try:
            with open(LOGIN_LOGS_FILE, 'r') as f:
                logs = json.load(f)
        except:
            logs = []
    
    # Count previous attempts for this IP in the last 24 hours (simplified)
    attempts_count = sum(1 for log in logs if log['ip'] == ip_address) + 1
    
    new_log = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "time_only": datetime.now().strftime("%H:%M:%S"),
        "username": username,
        "status": status,
        "ip": ip_address,
        "attempts": attempts_count,
        "service": "Web Login",
        "proto": "http",
        "state": "FIN" if status == "Success" else "REQ"
    }
    
    logs.insert(0, new_log) # Newest first
    with open(LOGIN_LOGS_FILE, 'w') as f:
        json.dump(logs[:100], f, indent=2) # Keep last 100 logs

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Blocked senders storage
BLOCKED_SENDERS_FILE = 'blocked_senders.json'

def load_blocked_senders():
    """Load blocked senders from JSON file"""
    if os.path.exists(BLOCKED_SENDERS_FILE):
        try:
            with open(BLOCKED_SENDERS_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_blocked_senders(blocked):
    """Save blocked senders to JSON file"""
    with open(BLOCKED_SENDERS_FILE, 'w') as f:
        json.dump(blocked, f, indent=2)

def extract_email_address(sender):
    """Extract email address from sender string"""
    import re
    match = re.search(r'<(.+?)>', sender)
    if match:
        return match.group(1).lower()
    return sender.lower()




# If modifying these scopes, delete the file token.json.
# If modifying these scopes, delete the file token.json.
SCOPES = [
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/userinfo.email',
    'openid'
]

def get_gmail_service():
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists('credentials.json'):
                print("No credentials.json found.")
                # We can't proceed with Gmail without credentials
                return None
            
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    try:
        service = build('gmail', 'v1', credentials=creds)
        return service
    except HttpError as error:
        print(f'An error occurred: {error}')
        return None

def fetch_gmail_messages(service, max_results=10):
    try:
        # Call the Gmail API
        results = service.users().messages().list(userId='me', maxResults=max_results).execute()
        messages = results.get('messages', [])

        email_data = []

        if not messages:
            print('No messages found.')
            return []

        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            headers = msg['payload']['headers']
            
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
            sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
            
            # Simple snippet from the API
            snippet = msg.get('snippet', '')

            # LLM Analysis
            risk_score, risk_reason, risk_level = llm_engine.analyze_email(sender, subject, snippet)
            
            category = "Safe"
            if risk_score > 40: category = "High"
            if risk_score > 70: category = "Critical"

            email_data.append({
                "id": message['id'],
                "sender": sender,
                "subject": subject,
                "snippet": snippet,
                "timestamp": datetime.fromtimestamp(int(msg['internalDate'])/1000).strftime("%H:%M"),
                "risk_score": risk_score,
                "risk_reason": risk_reason,
                "is_unread": 'UNREAD' in msg['labelIds'],
                "category": category
            })
            
        return email_data

    except HttpError as error:
        print(f'An error occurred: {error}')
        return []


# Helper to extract email address removed for brevity if needed elsewhere

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # In a real app, we use request.remote_addr. 
        # For our "AI Wars" simulation, we allow the attacker AI to spoof IPs via a header.
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        
        # Default credentials for demo — set via environment variables or replace placeholders
        if username == os.environ.get('DEFAULT_ADMIN_USER', 'PASTE_ADMIN_USERNAME') and password == os.environ.get('DEFAULT_ADMIN_PASS', 'PASTE_ADMIN_PASSWORD'):
            session['logged_in'] = True
            session['username'] = username
            log_login_attempt(username, "Success", ip_address)
            return redirect(url_for('index'))
        else:
            log_login_attempt(username or "Unknown", "Failure", ip_address)
            error = 'Invalid credentials. Please try again. (Set DEFAULT_ADMIN_USER and DEFAULT_ADMIN_PASS env vars to enable default login)'

            
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear() # Clear all session data
    return redirect(url_for('login'))

@app.route('/auth/google')
def google_login():
    """Starts the Google OAuth flow"""
    try:
        if not os.path.exists('credentials.json'):
            return "credentials.json not found. Please provide it for OAuth.", 500
            
        flow = InstalledAppFlow.from_client_secrets_file(
            'credentials.json', SCOPES)
        creds = flow.run_local_server(port=0)
        
        # Save for future use (if needed for APIs)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
            
        # Get user info
        service = build('oauth2', 'v2', credentials=creds)
        user_info = service.userinfo().get().execute()
        
        # Set session
        session['logged_in'] = True
        session['username'] = user_info.get('name', 'User')
        session['user_email'] = user_info.get('email', '')
        session['user_picture'] = user_info.get('picture', '')
        
        log_login_attempt(session['user_email'], "Success (Google)", "OAuth Flow")
        
        return redirect(url_for('index'))
    except Exception as e:
        print(f"Google Auth Error: {e}")
        return f"Authentication failed: {str(e)}", 500

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/api/emails')
def get_emails():
    # Attempt to use real Gmail API
    service = get_gmail_service()
    
    if service:
        print("Fetching from Gmail API...")
        emails = fetch_gmail_messages(service)
    else:
        print("Gmail Authentication failed or service unavailable.")
        return jsonify({"error": "Authentication required", "auth_status": "failed"}), 401

    # Load blocked senders
    blocked_senders = load_blocked_senders()
    
    # Process emails and mark blocked status
    final_emails = []
    for email in emails:
        sender_email = extract_email_address(email['sender'])
        
        # Auto-block senders with score >90%
        if email['risk_score'] > 90 and sender_email not in blocked_senders:
            blocked_senders[sender_email] = {
                "blocked_at": datetime.now().isoformat(),
                "reason": f"Auto-blocked ({email['risk_score']}% threat)",
                "email_subject": email['subject'],
                "auto_blocked": True
            }
            save_blocked_senders(blocked_senders)
            email['auto_blocked'] = True

            if service:
                try:
                    service.users().messages().batchModify(
                        userId='me',
                        body={'ids': [email['id']], 'addLabelIds': ['SPAM'], 'removeLabelIds': ['INBOX']}
                    ).execute()
                    print(f"Auto-blocked {email['id']} and moved to SPAM")
                except Exception as e:
                    print(f"Error moving {email['id']} to SPAM: {e}")
        
        # Always include in final list, but mark if blocked
        if sender_email in blocked_senders:
            email['is_blocked'] = True
            email['block_info'] = blocked_senders[sender_email]
        
        final_emails.append(email)

    # Sort: Newest first
    final_emails.sort(key=lambda x: x['timestamp'], reverse=True)
    
    stats = {
        "total_scanned": 1243 + len(emails),
        "threats_blocked": len(blocked_senders),
        "system_status": "Active Monitoring" if service else "Simulation Mode"
    }
    
    return jsonify({"emails": final_emails, "stats": stats})

@app.route('/api/block', methods=['POST'])
def block_sender():
    data = request.json
    sender = data.get('sender')
    reason = data.get('reason', 'Manually blocked')
    subject = data.get('subject', '')
    
    if not sender:
        return jsonify({"error": "Sender required"}), 400
    
    sender_email = extract_email_address(sender)
    blocked_senders = load_blocked_senders()
    
    blocked_senders[sender_email] = {
        "blocked_at": datetime.now().isoformat(),
        "reason": reason,
        "email_subject": subject,
        "auto_blocked": False
    }
    
    save_blocked_senders(blocked_senders)
    
    # Move message to SPAM if service is available and message_id is provided
    message_id = data.get('message_id')
    if message_id:
        service = get_gmail_service()
        if service:
            try:
                service.users().messages().batchModify(
                    userId='me',
                    body={
                        'ids': [message_id],
                        'addLabelIds': ['SPAM'],
                        'removeLabelIds': ['INBOX']
                    }
                ).execute()
                print(f"Moved message {message_id} to SPAM")
            except Exception as e:
                print(f"Error moving message to SPAM: {e}")

    return jsonify({"success": True, "message": f"Blocked {sender_email} and moved to SPAM"})

@app.route('/api/unblock', methods=['POST'])
def unblock_sender():
    data = request.json
    sender_email = data.get('sender_email')
    
    if not sender_email:
        return jsonify({"error": "Sender email required"}), 400
    
    blocked_senders = load_blocked_senders()
    
    if sender_email in blocked_senders:
        del blocked_senders[sender_email]
        save_blocked_senders(blocked_senders)
        return jsonify({"success": True, "message": f"Unblocked {sender_email}"})
    
    return jsonify({"error": "Sender not found in blocked list"}), 404

@app.route('/api/blocked')
def get_blocked():
    blocked_senders = load_blocked_senders()
    # Convert to list format for frontend
    blocked_list = []
    for email, data in blocked_senders.items():
        blocked_list.append({
            "email": email,
            **data
        })
    return jsonify({"blocked_senders": blocked_list})

@app.route('/api/profile')
@login_required
def get_user_profile():
    try:
        # Priority 1: Data from current session (Google Login)
        if 'user_email' in session:
            return jsonify({
                "name": session.get('username', 'User Account'),
                "email": session.get('user_email', ''),
                "picture": session.get('user_picture', '')
            })
        
        # Priority 2: Fallback to token.json if available
        creds = None
        if os.path.exists('token.json'):
            creds = Credentials.from_authorized_user_file('token.json', SCOPES)
        
        if not creds or not creds.valid:
            # Priority 3: Default admin user if logged in manually
            if session.get('username') == os.environ.get('DEFAULT_ADMIN_USER','PASTE_ADMIN_USERNAME'):
                return jsonify({
                    "name": "Admin User",
                    "email": "admin@aegisai.ai",
                    "picture": ""
                })
            return jsonify({"error": "Not authenticated"}), 401
    except HttpError as error:
        print(f'An error occurred fetching profile: {error}')
        return jsonify({"error": "Failed to fetch profile"}), 500
    except Exception as e:
        print(f'Unexpected error: {e}')
        return jsonify({"error": "Failed to fetch profile", "details": str(e)}), 500

@app.route('/api/login-logs')
@login_required
def get_login_logs():
    try:
        logs = []
        if os.path.exists(LOGIN_LOGS_FILE):
            with open(LOGIN_LOGS_FILE, 'r') as f:
                logs = json.load(f)
        
        # Process logs through the threat engine for consistent categorization/scoring
        display_logs = login_engine.process_real_logs(logs)
        
        # Add some mock traffic if history is short to show diversity (DDoS, etc.)
        if len(display_logs) < 10:
            mock_logs = login_engine.generate_mock_login_traffic(count=10 - len(display_logs))
            display_logs.extend(mock_logs)
            
        # Calculate stats
        threat_count = sum(1 for log in display_logs if log['category'] != 'Normal')
        
        return jsonify({
            "logs": display_logs,
            "stats": {
                "recent_threats": threat_count,
                "total_monitored": len(display_logs)
            }
        })
    except Exception as e:
        print(f"Error in login-logs: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/bank-transactions')
def get_bank_transactions():
    try:
        transactions = money_engine.generate_transactions(count=15)
        # Calculate some summary stats
        fraud_alerts = [t for t in transactions if t['is_fraud']]
        
        return jsonify({
            "account_id": money_engine.selected_account,
            "transactions": transactions,
            "summary": {
                "total_transactions": len(transactions),
                "fraud_alerts": len(fraud_alerts)
            }
        })
    except Exception as e:
        print(f"Error in bank-transactions: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/health')
def health_check():
    return jsonify({"status": "healthy", "time": datetime.now().isoformat()})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
