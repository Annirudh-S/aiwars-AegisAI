from app import app, log_login_attempt, LOGIN_LOGS_FILE
import os
import json

def test_login_logging():
    print("Testing Login Logging...")
    test_ip = "127.0.0.1"
    
    # Clean up previous tests
    if os.path.exists(LOGIN_LOGS_FILE):
        os.remove(LOGIN_LOGS_FILE)
    
    # Test Success
    log_login_attempt("admin", "Success", test_ip)
    
    # Test Failure
    log_login_attempt("user1", "Failure", test_ip)
    log_login_attempt("user1", "Failure", test_ip)
    
    # Verify File
    if os.path.exists(LOGIN_LOGS_FILE):
        with open(LOGIN_LOGS_FILE, 'r') as f:
            logs = json.load(f)
            print(f"Total Logs: {len(logs)}")
            for log in logs:
                print(f"[{log['timestamp']}] {log['username']} - {log['status']} (Attempts: {log['attempts']})")
    else:
        print("FAILED: login_attempts.json not created")

def test_routes():
    print("\nTesting Application Routes...")
    with app.test_client() as client:
        # Test redirect from root
        response = client.get('/')
        print(f"Root URL (Expected 302): {response.status_code}")
        
        # Test login page
        response = client.get('/login')
        print(f"Login Page (Expected 200): {response.status_code}")
        
        # Test failed login
        response = client.post('/login', data={'username': 'admin', 'password': 'wrongpassword'})
        print(f"Failed Login (Expected 200 with error): {response.status_code}")
        
        # Test successful login
        response = client.post('/login', data={'username': 'admin', 'password': 'password123'}, follow_redirects=True)
        print(f"Successful Login (Expected 200 after redirect): {response.status_code}")
        
        # Test logout
        response = client.get('/logout', follow_redirects=True)
        print(f"Logout (Expected 200 after redirect): {response.status_code}")

if __name__ == "__main__":
    test_login_logging()
    test_routes()
