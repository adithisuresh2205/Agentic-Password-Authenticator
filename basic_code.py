import pandas as pd
import secrets
import string
import re
import numpy as np
import hashlib
import requests
import io
import json
import base64
import math
import sys
import os

try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import Dense
except ImportError:
    print("TensorFlow not found. Please run: !pip install tensorflow")
    sys.exit()

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- Cryptographic Agent for Secure Key & Data Handling ---
class CryptoAgent:
    def derive_key(self, master_password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key

    def hash_password(self, password, salt):
        salted_password = salt + password.encode()
        return hashlib.sha256(salted_password).hexdigest()

    def encrypt(self, data, key):
        f = Fernet(key)
        return f.encrypt(data.encode()).decode()

    def decrypt(self, data, key):
        f = Fernet(key)
        return f.decrypt(data.encode()).decode()

class VaultAgent:
    VAULT_FILE = 'pass_vault.json'

    def __init__(self, crypto_agent):
        self.crypto_agent = crypto_agent
        self.key = None
        self.vault_data = {}
        self.hash_salt = None

    def create_vault(self, master_password):
        vault_salt = os.urandom(16)
        self.key = self.crypto_agent.derive_key(master_password, vault_salt)
        self.hash_salt = os.urandom(16)
        self.vault_data = {
            'vault_salt': base64.b64encode(vault_salt).decode(),
            'hash_salt': base64.b64encode(self.hash_salt).decode(),
            'passwords': {},
            'password_hashes': []
        }
        self._save_vault()
        return True

    def unlock_vault(self, master_password):
        try:
            with open(self.VAULT_FILE, 'r') as f:
                vault_structure = json.load(f)

            vault_salt = base64.b64decode(vault_structure['vault_salt'])
            derived_key = self.crypto_agent.derive_key(master_password, vault_salt)
            self.hash_salt = base64.b64decode(vault_structure['hash_salt'])
            self.vault_data = vault_structure
            self.key = derived_key

            return True
        except (IOError, ValueError, IndexError, base64.binascii.Error) as e:
            return False

    def save_password(self, service, username, password):
        if not self.key: return False

        password_hash = self.crypto_agent.hash_password(password, self.hash_salt)
        if password_hash in self.vault_data['password_hashes']:
            print("🛑 **SAVE DENIED!** This password is already in use for another service in your vault.")
            return False

        encrypted_password = self.crypto_agent.encrypt(password, self.key)

        if service not in self.vault_data['passwords']:
            self.vault_data['passwords'][service] = {}

        self.vault_data['passwords'][service][username] = encrypted_password
        self.vault_data['password_hashes'].append(password_hash)
        self._save_vault()
        return True

    def get_password(self, service, username):
        if not self.key or service not in self.vault_data['passwords'] or username not in self.vault_data['passwords'][service]:
            return None

        encrypted_password = self.vault_data['passwords'][service][username]
        decrypted_password = self.crypto_agent.decrypt(encrypted_password, self.key)
        return decrypted_password

    def _save_vault(self):
        encrypted_data = self.crypto_agent.encrypt(json.dumps(self.vault_data), self.key)
        vault_structure = {
            'vault_salt': self.vault_data['vault_salt'],
            'hash_salt': self.vault_data['hash_salt'],
            'encrypted_data': encrypted_data
        }
        with open(self.VAULT_FILE, 'w') as f:
            json.dump(vault_structure, f, indent=4)

# --- Perception, Suggestion, Risk, Explanations Agents ---
class PerceptionAgent:
    def __init__(self):
        self.keyboard_walks = ["qwert", "asdfg", "zxcvb", "123456", "password", "qwerty", "asdfgh", "abcdef"]
        self.common_words = {"password", "admin", "123456", "welcome", "secure", "football", "test", "love"}
        self.leetspeak_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
    def _is_sequence(self, password):
        pw_lower = password.lower()
        if re.search(r'(\d)\1{2,}', pw_lower): return True
        if re.search(r'(.+)\1{2,}', pw_lower): return True
        if '123' in pw_lower or '321' in pw_lower or 'abc' in pw_lower or 'cba' in pw_lower: return True
        return False
    def _is_leaked_password(self, password_hash, leaked_hashes):
        return password_hash in leaked_hashes if leaked_hashes else False
    def _contains_leetspeak(self, password):
        pw_lower = password.lower()
        for letter, sub in self.leetspeak_map.items():
            if sub in password and letter not in pw_lower:
                return True
        return False
    def extract_features(self, password, leaked_hashes=None):
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return {
            'length': len(password),
            'has_upper': any(c.isupper() for c in password),
            'has_lower': any(c.islower() for c in password),
            'has_digit': any(c.isdigit() for c in password),
            'has_symbol': any(c in string.punctuation for c in password),
            'is_common_word': password.lower() in self.common_words,
            'is_keyboard_walk': any(walk in password.lower() for walk in self.keyboard_walks),
            'has_year_suffix': bool(re.search(r'\d{2,4}$', password)) and len(password) > 4,
            'is_leaked': self._is_leaked_password(password_hash, leaked_hashes),
            'is_sequence': self._is_sequence(password),
            'is_leetspeak': self._contains_leetspeak(password),
        }

class SuggestionAgent:
    def __init__(self):
        self.wordlist_base = ["sky", "mango", "river", "blue", "tiger", "cloud", "ocean", "star", "jungle", "forest"]
        self.themed_wordlists = {
            'fantasy': ['dragon', 'sword', 'castle', 'wizard', 'potion', 'elf', 'knight', 'dungeon'],
            'sci-fi': ['robot', 'galaxy', 'laser', 'alien', 'planet', 'fusion', 'quantum', 'nebula'],
            'travel': ['voyage', 'summit', 'journey', 'horizon', 'explore', 'compass', 'atlas', 'wander'],
            'food': ['cookie', 'apple', 'banana', 'pizza', 'sushi', 'taco', 'burger', 'lemon'],
            'animals': ['lion', 'eagle', 'whale', 'panda', 'bear', 'wolf', 'shark', 'fox'],
        }
    def generate_suggestion(self, theme=None):
        words_to_use = []
        random_choice = secrets.SystemRandom()
        if theme and theme in self.themed_wordlists:
            words_to_use = random_choice.sample(self.themed_wordlists[theme], 2) + [random_choice.choice(self.wordlist_base)]
        else:
            words_to_use = random_choice.sample(self.wordlist_base, 3)
        digits = ''.join(random_choice.choice(string.digits) for _ in range(4))
        symbol1 = random_choice.choice(string.punctuation)
        symbol2 = random_choice.choice(string.punctuation)
        separator = random_choice.choice(['-', '_', '*'])
        passphrase = f"{words_to_use[0].capitalize()}{separator}{words_to_use[1].capitalize()}{symbol1}{words_to_use[2].capitalize()}{symbol2}{digits}"
        if any(word in passphrase.lower() for word in ["pass", "word", "123", "abc"]):
            return self.generate_suggestion(theme)
        return passphrase
    def generate_alternatives(self, theme=None, num_suggestions=3):
        return [self.generate_suggestion(theme) for _ in range(num_suggestions)]

class RiskAssessmentAgent:
    DATASET_URL = "https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/main/Real-Passwords/top_10000_passwords.txt" # Corrected URL
    def __init__(self, perception_agent, suggestion_agent):
        self.perception_agent = perception_agent
        self.suggestion_agent = suggestion_agent
        self.model, self.feature_names, self.leaked_hashes = self._train_model_with_dataset()
    def _download_dataset(self, url):
        print("Downloading the password dataset (10k entries)...")
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            print("Download complete.")
            return io.StringIO(response.text)
        except requests.RequestException as e:
            print(f"Error downloading dataset. Using internal fallback. Error: {e}")
            return io.StringIO("password\n123456\nqwerty\nadmin\n") # Simplified fallback
    def _create_dataset(self):
        leaked_file = self._download_dataset(self.DATASET_URL)
        # Assuming the file is just a list of passwords, one per line
        weak_passwords_list = leaked_file.read().splitlines()
        weak_passwords_list = weak_passwords_list[:10000] # Limit to 10000
        weak_passwords = pd.DataFrame({'password': weak_passwords_list})
        weak_passwords['strength'] = 1 # Mark as weak
        leaked_hashes = {hashlib.sha256(p.encode()).hexdigest() for p in weak_passwords['password']}
        num_strong = len(weak_passwords)
        strong_passwords_list = [self.suggestion_agent.generate_suggestion() for _ in range(num_strong)]
        strong_passwords = pd.DataFrame({'password': strong_passwords_list})
        strong_passwords['strength'] = 0 # Mark as strong
        combined_df = pd.concat([weak_passwords, strong_passwords]).sample(frac=1).reset_index(drop=True)
        print(f"Training dataset size: {len(combined_df)} entries.")
        return combined_df, leaked_hashes
    def _train_model_with_dataset(self):
        df, leaked_hashes = self._create_dataset()
        features_list = [self.perception_agent.extract_features(p, leaked_hashes=leaked_hashes) for p in df['password']]
        feature_names = list(features_list[0].keys())
        X = np.array([[f[name] for name in feature_names] for f in features_list])
        y = df['strength'].values
        model = Sequential([
            Dense(64, activation='relu', input_shape=(len(feature_names),)),
            Dense(32, activation='relu'),
            Dense(1, activation='sigmoid')
        ])
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        print("Training Neural Network...")
        model.fit(X, y, epochs=10, batch_size=32, verbose=0)
        print("Training complete.")
        return model, feature_names, leaked_hashes
    def get_risk_score(self, password):
        features = self.perception_agent.extract_features(password, leaked_hashes=self.leaked_hashes)
        if not password: return 0, 1.0, features
        feature_vector = np.array([features[name] for name in self.feature_names]).reshape(1, -1)
        print(f"Feature vector: {feature_vector}") # Added print for debugging
        breach_prob = self.model.predict(feature_vector, verbose=0)[0][0]
        # Handle potential NaN prediction
        if np.isnan(breach_prob):
            print("Warning: Model predicted NaN. Assigning default breach probability of 1.0.")
            breach_prob = 1.0
        safety_score = int((1 - breach_prob) * 100)
        return safety_score, breach_prob, features

class ExplanationsAgent:
    def generate_explanation(self, features):
        explanations = []
        if features['is_leaked']: explanations.append("🚨 **Breach Alert:** This password is known to have appeared in a past data breach. **Change this immediately.**")
        if features['is_common_word']: explanations.append("👎 **Common Word:** Your password uses a very common word.")
        if features['is_keyboard_walk']: explanations.append("🚶 **Predictable Pattern:** This password follows a common keyboard pattern.")
        if features['is_sequence']: explanations.append("🔢 **Simple Sequence:** The password contains a simple sequence of numbers or letters.")
        if features['has_year_suffix']: explanations.append("📅 **Year Suffix:** Adding a year is a common, predictable pattern.")
        if features['is_leetspeak']: explanations.append("👀 **Leetspeak:** Using simple character substitutions is easily reversed.")
        if features['length'] < 14: explanations.append(f"📏 **Too Short:** A longer password (14+ characters) is highly recommended.")
        if not (features['has_symbol'] and features['has_digit'] and features['has_upper']): explanations.append("🔡 **Low Variety:** For best security, mix uppercase, lowercase, numbers, and symbols.")
        if not explanations: explanations.append("✅ **Looks Great:** Your password is secure and does not show any common weaknesses.")
        return explanations

# --- The Proactive User Agent (The orchestrator & gatekeeper) ---

class ProactiveUserAgent:
    SECURITY_THRESHOLD = 70

    def __init__(self):
        self.crypto_agent = CryptoAgent()
        self.vault_agent = VaultAgent(self.crypto_agent)
        self.perception_agent = PerceptionAgent()
        self.suggestion_agent = SuggestionAgent()
        self.risk_agent = RiskAssessmentAgent(self.perception_agent, self.suggestion_agent)
        self.explanations_agent = ExplanationsAgent()
        self.logged_in = False

    def gatekeeper_check(self, password):
        score, _, features = self.risk_agent.get_risk_score(password)
        is_allowed = score >= self.SECURITY_THRESHOLD and not features['is_leaked']
        return is_allowed, score, features

    def live_password_check(self):
        print("\n🌐 **LIVE PASSWORD CHECK MODE**")
        print("The agent is actively monitoring your input. Type your password below.")
        print("Press Enter on an empty line to finalize your check.")

        full_password = ""
        while True:
            char_input = input(">> ")
            if not char_input:
                break
            full_password += char_input

            score, _, features = self.risk_agent.get_risk_score(full_password)
            is_allowed = score >= self.SECURITY_THRESHOLD and not features['is_leaked']

            print(f"   (LIVE SCORE: {score}/100)", end="")
            if not is_allowed:
                weakness = next((exp for exp in self.explanations_agent.generate_explanation(features) if not exp.startswith("✅")), None)
                if weakness:
                    print(f" | WARNING: {weakness.split(':')[0]}")
            print()

        if not full_password:
            print("No password entered. Exiting check.")
            return None

        is_allowed, final_score, final_features = self.gatekeeper_check(full_password)

        print("\n--- FINAL PASSWORD ANALYSIS ---")
        print(f"Final Password: '{full_password}'")
        print(f"AI Password Safety Score: {final_score}/100")

        if is_allowed:
            print("✅ **ACCESS GRANTED!** This password meets all security requirements.")
            return full_password
        else:
            print("🛑 **ACCESS DENIED!** This password is too weak.")
            print("\n**Reasons for Rejection:**")
            for exp in self.explanations_agent.generate_explanation(final_features):
                print(f" - {exp}")
            return None


    def run_interactive(self):
        print("==================================================================")
        print("          🔐 Agentic Password Manager Demo 🔑")
        print("==================================================================")

        if not self.vault_agent.unlock_vault('dummy_master_password'):
            print("Vault file not found. Let's create a new vault.")
            master_pass = input("Create a master password for your vault: ")
            self.vault_agent.create_vault(master_pass)
            print("Vault created. You are now logged in.")
            self.logged_in = True
        else:
            print("Welcome back! Please enter your master password to unlock the vault.")
            for _ in range(3):
                master_pass = input("Master Password: ")
                if self.vault_agent.unlock_vault(master_pass):
                    print("Vault unlocked. You are now logged in.")
                    self.logged_in = True
                    break
                else:
                    print("Incorrect master password. Please try again.")
            if not self.logged_in:
                print("Too many failed attempts. Exiting.")
                return

        while self.logged_in:
            print("\n------------------------------------------------------------------")
            print("Choose an action:")
            print("[L] **LIVE CHECK:** Check a password as you type")
            print("[G] Generate a new strong password")
            print("[S] Save a password to your vault")
            print("[V] View a saved password from your vault")
            print("[Q] Quit")

            action = input("Action: ").strip().lower()

            if action == 'q':
                print("Logging out. Goodbye!")
                break

            elif action == 'l':
                final_password = self.live_password_check()
                if final_password:
                    save_choice = input("Do you want to save this password? (y/n): ").strip().lower()
                    if save_choice == 'y':
                        service = input("Enter the service name to save for: ").strip()
                        username = input("Enter your username: ").strip()
                        self.vault_agent.save_password(service, username, final_password)
                        print(f"✅ Password saved for {service}!")

            elif action == 'g':
                theme_prompt = input("Enter a theme for suggestions (e.g., 'fantasy' or leave blank): ").strip().lower()
                suggestions = self.suggestion_agent.generate_alternatives(
                    theme=theme_prompt if theme_prompt in self.suggestion_agent.themed_wordlists else None)
                print("\n💡 Suggested passwords:")
                for sug in suggestions: print(f" - {sug}")

            elif action == 's':
                service = input("Enter the service name (e.g., Google): ").strip()
                username = input("Enter your username: ").strip()
                password = input("Enter the password to save: ").strip()
                is_allowed, score, features = self.gatekeeper_check(password)
                if is_allowed:
                    self.vault_agent.save_password(service, username, password)
                    print(f"\n✅ Password saved securely for {service}!")
                else:
                    print(f"\n🛑 **SAVE DENIED!** Password is too weak (Score: {score}/100).")
                    explanations = self.explanations_agent.generate_explanation(features)
                    for exp in explanations: print(f" - {exp}")

            elif action == 'v':
                service = input("Enter the service name: ").strip()
                username = input("Enter the username: ").strip()
                retrieved_pass = self.vault_agent.get_password(service, username)
                if retrieved_pass:
                    print(f"\n🔑 Password for {username}@{service}: {retrieved_pass}")
                else:
                    print("\n❌ Password not found. Please check the service and username.")

            else:
                print("Invalid action. Please choose from the menu.")

            print("="*70)

if __name__ == "__main__":
    orchestrator = ProactiveUserAgent()
    orchestrator.run_interactive()
