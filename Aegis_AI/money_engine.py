import random
from datetime import datetime, timedelta

class MoneyThreatEngine:
    def __init__(self):
        self.transaction_types = ['Transfer', 'Withdrawal', 'Deposit', 'Online Payment', 'ATM']
        self.merchants = ['Amazon', 'Walmart', 'Steam', 'Grocery Store', 'Unknown Tech Store', 'Netflix', 'Gas Station', 'Luxury Watch Shop']
        self.locations = ['New York', 'London', 'Berlin', 'Mumbai', 'Tokyo', 'San Francisco', 'Moscow', 'Cayman Islands']
        self.accounts = [f"ACC-{random.randint(10000, 99999)}" for _ in range(5)]
        self.selected_account = random.choice(self.accounts)
        self.transactions = []
        # Pre-seed with transactions
        self.initialize_transactions(count=15)

    def initialize_transactions(self, count=15):
        base_time = datetime.now() - timedelta(days=1)
        for i in range(count):
            self.transactions.append(self._create_single_transaction(base_time + timedelta(hours=i)))
        self.transactions.sort(key=lambda x: x['date'], reverse=True)

    def _create_single_transaction(self, timestamp):
        tx_type = random.choice(self.transaction_types)
        amount = round(random.uniform(5.0, 500.0), 2)
        location = random.choice(self.locations)
        
        is_fraud = False
        risk_score = random.randint(1, 15)
        reason = "Standard transaction pattern."

        if amount > 400 and location in ['Cayman Islands', 'Moscow']:
            is_fraud = True
            risk_score = random.randint(85, 98)
            reason = "Large transaction from high-risk offshore location."
        elif tx_type == 'Online Payment' and amount > 300 and random.random() < 0.2:
            is_fraud = True
            risk_score = random.randint(75, 92)
            reason = "Suspicious online purchase amount detected."

        return {
            "transaction_id": f"TXN-{random.randint(1000000, 9999999)}",
            "account_id": self.selected_account,
            "amount": amount,
            "date": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "type": tx_type,
            "location": location,
            "merchant": random.choice(self.merchants),
            "risk_score": risk_score,
            "is_fraud": is_fraud,
            "reason": reason
        }

    def generate_transactions(self, count=None):
        # Occasionally add a new transaction to the list (simulating real-time activity)
        if random.random() < 0.3: # 30% chance to see a new transaction on poll
            new_tx = self._create_single_transaction(datetime.now())
            self.transactions.insert(0, new_tx)
            # Keep history to a reasonable size
            self.transactions = self.transactions[:25]
            
        return self.transactions

money_engine = MoneyThreatEngine()
