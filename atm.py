import json
import os
import logging
from decimal import Decimal
from datetime import datetime
from typing import Optional, Tuple, List, Dict
import hashlib
import secrets
import tempfile
import shutil

# ============================================
# CONFIGURATION
# ============================================
class ATMConfig:
    """Centralized configuration for ATM system"""
    MAX_PIN_ATTEMPTS = 3
    MIN_DEPOSIT = Decimal('0.01')
    MAX_WITHDRAWAL = Decimal('5000.00')
    MIN_WITHDRAWAL = Decimal('10.00')
    DAILY_WITHDRAWAL_LIMIT = Decimal('10000.00')
    DATA_FILE = "atm_data.json"
    LOG_FILE = "atm_transactions.log"
    SALT_LENGTH = 32
    
    # Account types with different privileges
    ACCOUNT_TYPES = {
        'SAVINGS': {'interest_rate': Decimal('0.02'), 'monthly_fee': Decimal('0')},
        'CHECKING': {'interest_rate': Decimal('0.001'), 'monthly_fee': Decimal('5')},
        'PREMIUM': {'interest_rate': Decimal('0.03'), 'monthly_fee': Decimal('0')}
    }

# ============================================
# LOGGING SETUP
# ============================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(ATMConfig.LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('ATM_System')

# ============================================
# SECURITY MODULE
# ============================================
class SecurityManager:
    """Handles all security-related operations"""
    
    @staticmethod
    def hash_pin(pin: str, salt: str = None) -> Tuple[str, str]:
        """Hash PIN with salt using SHA-256"""
        if salt is None:
            salt = secrets.token_hex(ATMConfig.SALT_LENGTH)
        
        pin_hash = hashlib.pbkdf2_hmac(
            'sha256',
            pin.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # iterations
        )
        return pin_hash.hex(), salt
    
    @staticmethod
    def verify_pin(stored_hash: str, stored_salt: str, input_pin: str) -> bool:
        """Verify PIN against stored hash"""
        new_hash, _ = SecurityManager.hash_pin(input_pin, stored_salt)
        return new_hash == stored_hash
    
    @staticmethod
    def validate_pin_format(pin: str) -> Tuple[bool, str]:
        """Validate PIN meets security requirements"""
        if not pin.isdigit():
            return False, "PIN must contain only digits"
        if len(pin) < 4 or len(pin) > 6:
            return False, "PIN must be 4-6 digits"
        if pin == pin[0] * len(pin):
            return False, "PIN cannot be all same digits"
        return True, "Valid PIN"

# ============================================
# TRANSACTION HISTORY
# ============================================
class Transaction:
    """Represents a single transaction"""
    
    def __init__(self, transaction_type: str, amount: Decimal, 
                 balance_after: Decimal, notes: str = ""):
        self.timestamp = datetime.now().isoformat()
        self.type = transaction_type
        self.amount = amount
        self.balance_after = balance_after
        self.notes = notes
    
    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp,
            'type': self.type,
            'amount': str(self.amount),
            'balance_after': str(self.balance_after),
            'notes': self.notes
        }
    
    def __str__(self) -> str:
        return (f"[{self.timestamp}] {self.type}: ${self.amount:.2f} "
                f"(Balance: ${self.balance_after:.2f}) {self.notes}")

# ============================================
# ACCOUNT CLASS
# ============================================
class Account:
    """Enhanced Account class with security and features"""
    
    def __init__(self, username: str, pin_hash: str, salt: str,
                 balance: Decimal = Decimal('0'), 
                 account_type: str = 'CHECKING',
                 history: List[Dict] = None,
                 daily_withdrawn: Decimal = Decimal('0'),
                 last_withdrawal_date: str = None):
        self.username = username
        self.pin_hash = pin_hash
        self.salt = salt
        self.balance = Decimal(str(balance))
        self.account_type = account_type
        self.history = history if history else []
        self.daily_withdrawn = Decimal(str(daily_withdrawn))
        self.last_withdrawal_date = last_withdrawal_date
        self._failed_attempts = 0
        self._locked = False
    
    def verify_pin(self, input_pin: str) -> bool:
        """Verify PIN with attempt tracking"""
        if self._locked:
            logger.warning(f"Login attempt on locked account: {self.username}")
            return False
        
        if SecurityManager.verify_pin(self.pin_hash, self.salt, input_pin):
            self._failed_attempts = 0
            return True
        
        self._failed_attempts += 1
        if self._failed_attempts >= ATMConfig.MAX_PIN_ATTEMPTS:
            self._locked = True
            logger.critical(f"Account locked due to failed attempts: {self.username}")
        
        return False
    
    def reset_daily_limit_if_needed(self):
        """Reset daily withdrawal counter if it's a new day"""
        today = datetime.now().date().isoformat()
        if self.last_withdrawal_date != today:
            self.daily_withdrawn = Decimal('0')
            self.last_withdrawal_date = today
    
    def deposit(self, amount: Decimal) -> Tuple[bool, str]:
        """Deposit money with validation"""
        amount = Decimal(str(amount))
        
        if amount < ATMConfig.MIN_DEPOSIT:
            return False, f"Minimum deposit is ${ATMConfig.MIN_DEPOSIT}"
        
        if amount > Decimal('50000'):
            return False, "Single deposit cannot exceed $50,000 (fraud prevention)"
        
        self.balance += amount
        transaction = Transaction('DEPOSIT', amount, self.balance)
        self.history.append(transaction.to_dict())
        
        logger.info(f"Deposit: {self.username} deposited ${amount:.2f}")
        return True, f"${amount:.2f} deposited successfully. New balance: ${self.balance:.2f}"
    
    def withdraw(self, amount: Decimal) -> Tuple[bool, str]:
        """Withdraw money with enhanced validation"""
        amount = Decimal(str(amount))
        
        # Validation checks
        if amount < ATMConfig.MIN_WITHDRAWAL:
            return False, f"Minimum withdrawal is ${ATMConfig.MIN_WITHDRAWAL}"
        
        if amount > ATMConfig.MAX_WITHDRAWAL:
            return False, f"Maximum single withdrawal is ${ATMConfig.MAX_WITHDRAWAL}"
        
        if amount > self.balance:
            return False, f"Insufficient funds. Available: ${self.balance:.2f}"
        
        # Check daily limit
        self.reset_daily_limit_if_needed()
        if self.daily_withdrawn + amount > ATMConfig.DAILY_WITHDRAWAL_LIMIT:
            remaining = ATMConfig.DAILY_WITHDRAWAL_LIMIT - self.daily_withdrawn
            return False, f"Daily limit exceeded. Remaining today: ${remaining:.2f}"
        
        # Process withdrawal
        self.balance -= amount
        self.daily_withdrawn += amount
        transaction = Transaction('WITHDRAWAL', amount, self.balance)
        self.history.append(transaction.to_dict())
        
        logger.info(f"Withdrawal: {self.username} withdrew ${amount:.2f}")
        return True, f"${amount:.2f} withdrawn successfully. New balance: ${self.balance:.2f}"
    
    def transfer(self, recipient: 'Account', amount: Decimal) -> Tuple[bool, str]:
        """Transfer money to another account"""
        amount = Decimal(str(amount))
        
        if amount <= 0:
            return False, "Transfer amount must be positive"
        
        if amount > self.balance:
            return False, f"Insufficient funds. Available: ${self.balance:.2f}"
        
        if amount > Decimal('10000'):
            return False, "Single transfer cannot exceed $10,000"
        
        # Deduct from sender
        self.balance -= amount
        sender_tx = Transaction('TRANSFER_OUT', amount, self.balance, 
                               f"To: {recipient.username}")
        self.history.append(sender_tx.to_dict())
        
        # Add to recipient
        recipient.balance += amount
        recipient_tx = Transaction('TRANSFER_IN', amount, recipient.balance,
                                   f"From: {self.username}")
        recipient.history.append(recipient_tx.to_dict())
        
        logger.info(f"Transfer: {self.username} -> {recipient.username}: ${amount:.2f}")
        return True, f"${amount:.2f} transferred to {recipient.username}"
    
    def calculate_interest(self) -> Decimal:
        """Calculate interest based on account type"""
        config = ATMConfig.ACCOUNT_TYPES[self.account_type]
        interest = self.balance * config['interest_rate'] / Decimal('12')  # Monthly
        return interest.quantize(Decimal('0.01'))
    
    def apply_monthly_fees(self) -> Tuple[Decimal, Decimal]:
        """Apply monthly fees and interest"""
        config = ATMConfig.ACCOUNT_TYPES[self.account_type]
        interest = self.calculate_interest()
        fee = config['monthly_fee']
        
        net_change = interest - fee
        self.balance += net_change
        
        if interest > 0:
            tx = Transaction('INTEREST', interest, self.balance, "Monthly interest")
            self.history.append(tx.to_dict())
        
        if fee > 0:
            tx = Transaction('FEE', fee, self.balance, "Monthly maintenance fee")
            self.history.append(tx.to_dict())
        
        return interest, fee
    
    def get_transaction_history(self, limit: int = 10) -> List[str]:
        """Get formatted transaction history"""
        recent = self.history[-limit:] if len(self.history) > limit else self.history
        return [
            f"[{tx['timestamp'][:19]}] {tx['type']}: ${Decimal(tx['amount']):.2f} "
            f"(Balance: ${Decimal(tx['balance_after']):.2f})"
            for tx in reversed(recent)
        ]
    
    def to_dict(self) -> Dict:
        """Serialize account to dictionary"""
        return {
            'pin_hash': self.pin_hash,
            'salt': self.salt,
            'balance': str(self.balance),
            'account_type': self.account_type,
            'history': self.history,
            'daily_withdrawn': str(self.daily_withdrawn),
            'last_withdrawal_date': self.last_withdrawal_date
        }

# ============================================
# ATM SYSTEM
# ============================================
class ATM:
    """Enhanced ATM system with enterprise features"""
    
    def __init__(self):
        self.accounts: Dict[str, Account] = {}
        self.load_data()
    
    def load_data(self):
        """Load accounts with error handling"""
        if not os.path.exists(ATMConfig.DATA_FILE):
            logger.info("No data file found. Creating default accounts.")
            self.create_default_data()
            return
        
        try:
            with open(ATMConfig.DATA_FILE, 'r') as file:
                data = json.load(file)
                for username, details in data.items():
                    self.accounts[username] = Account(
                        username=username,
                        pin_hash=details['pin_hash'],
                        salt=details['salt'],
                        balance=details['balance'],
                        account_type=details.get('account_type', 'CHECKING'),
                        history=details.get('history', []),
                        daily_withdrawn=details.get('daily_withdrawn', '0'),
                        last_withdrawal_date=details.get('last_withdrawal_date')
                    )
            logger.info(f"Loaded {len(self.accounts)} accounts successfully")
        except Exception as e:
            logger.error(f"Error loading data: {e}")
            print("Error loading data. Starting fresh.")
            self.create_default_data()
    
    def create_default_data(self):
        """Create default accounts with hashed PINs"""
        defaults = {
            "Alice": {"pin": "1234", "balance": 1500.0, "type": "PREMIUM"},
            "Bob": {"pin": "5678", "balance": 800.0, "type": "CHECKING"},
            "Charlie": {"pin": "9012", "balance": 1200.0, "type": "SAVINGS"}
        }
        
        for username, data in defaults.items():
            pin_hash, salt = SecurityManager.hash_pin(data['pin'])
            self.accounts[username] = Account(
                username=username,
                pin_hash=pin_hash,
                salt=salt,
                balance=Decimal(str(data['balance'])),
                account_type=data['type']
            )
        
        self.save_data()
        logger.info("Default accounts created")
    
    def save_data(self):
        """Atomic save to prevent data corruption"""
        data_to_save = {name: acc.to_dict() for name, acc in self.accounts.items()}
        
        # Write to temporary file first
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, 
                                                suffix='.json')
        try:
            json.dump(data_to_save, temp_file, indent=4)
            temp_file.close()
            
            # Atomic replace
            shutil.move(temp_file.name, ATMConfig.DATA_FILE)
            logger.info("Data saved successfully")
        except Exception as e:
            logger.error(f"Error saving data: {e}")
            if os.path.exists(temp_file.name):
                os.unlink(temp_file.name)
            raise
    
    def create_account(self):
        """Create a new account interactively"""
        print("\n=== Create New Account ===")
        
        username = input("Enter username: ").strip()
        if username in self.accounts:
            print("Username already exists!")
            return
        
        while True:
            pin = input("Enter 4-6 digit PIN: ").strip()
            valid, msg = SecurityManager.validate_pin_format(pin)
            if valid:
                break
            print(f"Invalid PIN: {msg}")
        
        print("\nAccount Types:")
        for i, (acc_type, config) in enumerate(ATMConfig.ACCOUNT_TYPES.items(), 1):
            print(f"{i}. {acc_type} - Interest: {config['interest_rate']*100}% "
                  f"Monthly Fee: ${config['monthly_fee']}")
        
        choice = input("Choose account type (1-3): ").strip()
        acc_types = list(ATMConfig.ACCOUNT_TYPES.keys())
        account_type = acc_types[int(choice)-1] if choice in '123' else 'CHECKING'
        
        try:
            initial = Decimal(input("Initial deposit ($): ").strip())
            if initial < ATMConfig.MIN_DEPOSIT:
                print(f"Minimum deposit is ${ATMConfig.MIN_DEPOSIT}")
                return
        except:
            print("Invalid amount")
            return
        
        pin_hash, salt = SecurityManager.hash_pin(pin)
        self.accounts[username] = Account(
            username=username,
            pin_hash=pin_hash,
            salt=salt,
            balance=initial,
            account_type=account_type
        )
        
        self.save_data()
        print(f"\n✓ Account created successfully for {username}!")
        logger.info(f"New account created: {username} ({account_type})")
    
    def login(self) -> Optional[Account]:
        """Enhanced login with better security"""
        print("\n" + "="*50)
        print("   ENTERPRISE ATM SYSTEM v2.0")
        print("="*50)
        print("\n1. Login to existing account")
        print("2. Create new account")
        print("3. Exit")
        
        choice = input("\nChoose option: ").strip()
        
        if choice == "2":
            self.create_account()
            return None
        elif choice == "3":
            print("Goodbye!")
            exit(0)
        
        username = input("\nEnter username: ").strip()
        
        if username not in self.accounts:
            logger.warning(f"Login attempt with non-existent username: {username}")
            print("Account not found.")
            return None
        
        account = self.accounts[username]
        
        if account._locked:
            print("❌ Account is locked. Contact administrator.")
            return None
        
        attempts = 0
        while attempts < ATMConfig.MAX_PIN_ATTEMPTS:
            pin = input("Enter PIN: ").strip()
            
            if account.verify_pin(pin):
                print(f"\n✓ Login successful! Welcome, {username}.")
                print(f"Account Type: {account.account_type}")
                logger.info(f"Successful login: {username}")
                return account
            
            attempts += 1
            remaining = ATMConfig.MAX_PIN_ATTEMPTS - attempts
            if remaining > 0:
                print(f"❌ Incorrect PIN. {remaining} attempt(s) remaining.")
            logger.warning(f"Failed login attempt for {username}")
        
        print("🔒 Account locked due to too many failed attempts.")
        return None
    
    def display_menu(self, account: Account):
        """Display main menu"""
        print(f"\n{'='*50}")
        print(f"  Account: {account.username} ({account.account_type})")
        print(f"  Balance: ${account.balance:.2f}")
        print(f"{'='*50}")
        print("\n1. Check Detailed Balance")
        print("2. Deposit")
        print("3. Withdraw")
        print("4. Transfer to Another Account")
        print("5. Transaction History")
        print("6. Account Information")
        print("7. Calculate Monthly Interest")
        print("8. Logout")
    
    def handle_transfer(self, account: Account):
        """Handle money transfer"""
        print("\n=== Transfer Money ===")
        print("Available accounts:")
        for name in self.accounts.keys():
            if name != account.username:
                print(f"  - {name}")
        
        recipient_name = input("\nRecipient username: ").strip()
        
        if recipient_name not in self.accounts:
            print("Recipient not found.")
            return
        
        if recipient_name == account.username:
            print("Cannot transfer to yourself.")
            return
        
        try:
            amount = Decimal(input("Amount to transfer: $").strip())
            success, msg = account.transfer(self.accounts[recipient_name], amount)
            print(msg)
            if success:
                self.save_data()
        except ValueError:
            print("Invalid amount.")
    
    def show_account_info(self, account: Account):
        """Display detailed account information"""
        print("\n" + "="*50)
        print("  ACCOUNT INFORMATION")
        print("="*50)
        print(f"Username: {account.username}")
        print(f"Account Type: {account.account_type}")
        print(f"Current Balance: ${account.balance:.2f}")
        print(f"Daily Withdrawn: ${account.daily_withdrawn:.2f} / ${ATMConfig.DAILY_WITHDRAWAL_LIMIT:.2f}")
        print(f"Total Transactions: {len(account.history)}")
        
        config = ATMConfig.ACCOUNT_TYPES[account.account_type]
        print(f"Interest Rate: {config['interest_rate']*100}% annually")
        print(f"Monthly Fee: ${config['monthly_fee']}")
        print("="*50)
    
    def run(self):
        """Main application loop"""
        current_account = None
        
        while True:
            if not current_account:
                current_account = self.login()
                if not current_account:
                    continue
            
            self.display_menu(current_account)
            choice = input("\nChoose option: ").strip()
            
            if choice == "1":
                self.show_account_info(current_account)
            
            elif choice == "2":
                try:
                    amt = Decimal(input("Amount to deposit: $").strip())
                    success, msg = current_account.deposit(amt)
                    print(msg)
                    if success:
                        self.save_data()
                except ValueError:
                    print("Invalid amount.")
            
            elif choice == "3":
                try:
                    amt = Decimal(input("Amount to withdraw: $").strip())
                    success, msg = current_account.withdraw(amt)
                    print(msg)
                    if success:
                        self.save_data()
                except ValueError:
                    print("Invalid amount.")
            
            elif choice == "4":
                self.handle_transfer(current_account)
            
            elif choice == "5":
                print("\n=== Transaction History (Last 10) ===")
                history = current_account.get_transaction_history(10)
                if not history:
                    print("No transactions yet.")
                else:
                    for record in history:
                        print(record)
            
            elif choice == "6":
                self.show_account_info(current_account)
            
            elif choice == "7":
                interest = current_account.calculate_interest()
                config = ATMConfig.ACCOUNT_TYPES[current_account.account_type]
                fee = config['monthly_fee']
                net = interest - fee
                print(f"\n=== Monthly Calculation ===")
                print(f"Interest Earned: ${interest:.2f}")
                print(f"Monthly Fee: ${fee:.2f}")
                print(f"Net Change: ${net:.2f}")
                print(f"Projected Balance: ${current_account.balance + net:.2f}")
            
            elif choice == "8":
                print("Logging out... Goodbye!")
                logger.info(f"User logout: {current_account.username}")
                self.save_data()
                current_account = None
            
            else:
                print("Invalid option.")

# ============================================
# ENTRY POINT
# ============================================
if __name__ == "__main__":
    try:
        app = ATM()
        app.run()
    except KeyboardInterrupt:
        print("\n\nSystem shutting down...")
        logger.info("System shutdown via keyboard interrupt")
    except Exception as e:
        logger.critical(f"Critical system error: {e}", exc_info=True)
        print(f"\n❌ Critical error: {e}")