import requests
import json
import random
import string
import names
import time
import websocket as activation
import secrets
from datetime import datetime
from fake_useragent import UserAgent
from bs4 import BeautifulSoup
from colorama import init, Fore, Back, Style
from eth_account import Account
from eth_account.messages import encode_defunct
from websocket import create_connection

init(autoreset=True)

def load_proxies():
    try:
        with open('proxies.txt', 'r') as f:
            proxies = [line.strip() for line in f if line.strip()]
            
        valid_proxies = []
        for proxy in proxies:
            if not proxy.startswith(('http://', 'https://')):
                proxy = f'http://{proxy}'
            valid_proxies.append(proxy)
            
        if valid_proxies:
            print(f"{Fore.GREEN}Loaded {len(valid_proxies)} proxies\n{Fore.RESET}")
        return valid_proxies
    except FileNotFoundError:
        print(f"{Fore.YELLOW}proxies.txt not found, running without proxies\n{Fore.RESET}")
        return []

def get_random_proxy(proxies):
    if not proxies:
        return None
    return random.choice(proxies)

def log_message(account_num=None, total=None, message="", message_type="info"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    account_status = f"{account_num}/{total}" if account_num and total else ""
    
    colors = {
        "info": Fore.LIGHTWHITE_EX,
        "success": Fore.LIGHTGREEN_EX,
        "error": Fore.LIGHTRED_EX,
        "warning": Fore.LIGHTYELLOW_EX,
        "process": Fore.LIGHTCYAN_EX,
        "debug": Fore.LIGHTMAGENTA_EX
    }
    
    log_color = colors.get(message_type, Fore.LIGHTWHITE_EX)
    print(f"{Fore.WHITE}[{Style.DIM}{timestamp}{Style.RESET_ALL}{Fore.WHITE}] "
          f"{Fore.WHITE}[{Fore.LIGHTYELLOW_EX}{account_status}{Fore.WHITE}] "
          f"{log_color}{message}")

def generate_ethereum_wallet():
    private_key = '0x' + secrets.token_hex(32)
    account = Account.from_key(private_key)
    return {
        'address': account.address,
        'private_key': private_key
    }

def create_wallet_signature(wallet, message):
    account = Account.from_key(wallet['private_key'])
    signable_message = encode_defunct(text=message)
    signed_message = account.sign_message(signable_message)
    return signed_message.signature.hex()

class TeneoAutoref:
    def __init__(self, ref_code, proxy=None):
        self.ua = UserAgent()
        self.session = requests.Session()
        self.ref_code = ref_code
        self.proxy = proxy
        if proxy:
            self.proxies = {
                'http': proxy,
                'https': proxy
            }
        else:
            self.proxies = None
    
    def make_request(self, method, url, **kwargs):
        try:
            if self.proxies:
                kwargs['proxies'] = self.proxies
                kwargs['timeout'] = 60  
            
            response = requests.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            log_message(self.current_num, self.total, f"Request failed: {str(e)}", "error")
            if self.proxies:
                log_message(self.current_num, self.total, f"Failed proxy: {self.proxy}", "error")
            return None

    def get_random_domain(self):
        log_message(self.current_num, self.total, "Searching for available email domain...", "process")
        vowels = 'aeiou'
        consonants = 'bcdfghjklmnpqrstvwxyz'
        keyword = random.choice(consonants) + random.choice(vowels)
        
        headers = {'User-Agent': self.ua.random}
        response = self.make_request('GET', f'https://generator.email/search.php?key={keyword}', headers=headers, timeout=60)
        
        if not response:
            return None
            
        domains = response.json()
        valid_domains = [d for d in domains if all(ord(c) < 128 for c in d)]
        
        if valid_domains:
            selected_domain = random.choice(valid_domains)
            log_message(self.current_num, self.total, f"Selected domain: {selected_domain}", "success")
            return selected_domain
            
        log_message(self.current_num, self.total, "Could not find valid domain", "error")
        return None

    def generate_email(self, domain):
        log_message(self.current_num, self.total, "Generating email address...", "process")
        first_name = names.get_first_name().lower()
        last_name = names.get_last_name().lower()
        random_nums = ''.join(random.choices(string.digits, k=3))
        
        separator = random.choice(['', '.'])
        email = f"{first_name}{separator}{last_name}{random_nums}@{domain}"
        log_message(self.current_num, self.total, f"Email created: {email}", "success")
        return email

    def generate_password(self):
        log_message(self.current_num, self.total, "Generating password...", "process")
        first_letter = random.choice(string.ascii_uppercase)
        lower_letters = ''.join(random.choices(string.ascii_lowercase, k=4))
        numbers = ''.join(random.choices(string.digits, k=3))
        password = f"{first_letter}{lower_letters}@{numbers}"
        log_message(self.current_num, self.total, "Password created successfully", "success")
        return password

    def check_user_exists(self, email):
        log_message(self.current_num, self.total, "Checking email availability...", "process")
        headers = {
            "accept": "application/json, text/plain, */*",
            "content-type": "application/json",
            "x-api-key": "OwAG3kib1ivOJG4Y0OCZ8lJETa6ypvsDtGmdhcjA",
            "user-agent": self.ua.random,
            'Origin': 'https://dashboard.teneo.pro',
            'Referer': 'https://dashboard.teneo.pro/'
        }
        check_url = "https://auth.teneo.pro/api/check-user-exists"
        response = self.make_request('POST', check_url, headers=headers, json={"email": email}, timeout=60)
        
        if not response:
            return True
            
        exists = response.json().get("exists", True)
        
        if exists:
            log_message(self.current_num, self.total, "Email already registered", "error")
        else:
            log_message(self.current_num, self.total, "Email is available", "success")
        return exists

    def generate_valid_credentials(self):
        max_attempts = 5
        for attempt in range(max_attempts):
            domain = self.get_random_domain()
            if not domain:
                continue

            email = self.generate_email(domain)
            if not self.check_user_exists(email):
                return domain, email, self.generate_password()
            
            log_message(self.current_num, self.total, f"Retrying with new credentials (Attempt {attempt + 1}/{max_attempts})", "warning")
        
        return None, None, None

    def register_account(self, email, password):
        log_message(self.current_num, self.total, "Registering account...", "process")
        headers = {
            "accept": "*/*",
            "content-type": "application/json;charset=UTF-8",
            "apikey": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imlra25uZ3JneHV4Z2pocGxicGV5Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3MjU0MzgxNTAsImV4cCI6MjA0MTAxNDE1MH0.DRAvf8nH1ojnJBc3rD_Nw6t1AV8X_g6gmY_HByG2Mag",
            "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imlra25uZ3JneHV4Z2pocGxicGV5Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3MjU0MzgxNTAsImV4cCI6MjA0MTAxNDE1MH0.DRAvf8nH1ojnJBc3rD_Nw6t1AV8X_g6gmY_HByG2Mag",
            "user-agent": self.ua.random,
            'Origin': 'https://dashboard.teneo.pro',
            'Referer': 'https://dashboard.teneo.pro/'            
        }
        
        register_data = {
            "email": email,
            "password": password,
            "data": {"invited_by": self.ref_code},
            "gotrue_meta_security": {},
            "code_challenge": None,
            "code_challenge_method": None
        }
        
        register_url = "https://node-b.teneo.pro/auth/v1/signup"
        response = self.make_request('POST', register_url, headers=headers, json=register_data, timeout=60)
        
        if not response:
            return {"role": None}
            
        result = response.json()
        
        if result.get("role") == "authenticated":
            log_message(self.current_num, self.total, "Registration successful", "success")
        else:
            log_message(self.current_num, self.total, "Registration failed", "error")
        return result

    def get_verification_link(self, email, domain):
        log_message(self.current_num, self.total, "Waiting for verification email...", "process")
        cookies = {
            'embx': f'[%22{email}%22]',
            'surl': f'{domain}/{email.split("@")[0]}'
        }
        headers = {'User-Agent': self.ua.random}
        
        max_attempts = 5
        for attempt in range(max_attempts):
            log_message(self.current_num, self.total, f"Attempting to get verification link...", "process")
            response = self.make_request('GET', 'https://generator.email/inbox1/', headers=headers, cookies=cookies, timeout=60)
            
            if not response:
                continue
                
            soup = BeautifulSoup(response.text, 'html.parser')
            verify_link = soup.find('a', {'class': 'es-button'})
            
            if verify_link and 'verify' in verify_link.get('href', ''):
                log_message(self.current_num, self.total, "Verification link found", "success")
                return verify_link['href']

        log_message(self.current_num, self.total, "Could not find verification link", "error")
        return None

    def verify_email(self, verification_url):
        log_message(self.current_num, self.total, "Verifying email...", "process")
        
        initial_response = self.make_request('GET', verification_url, headers={'User-Agent': self.ua.random}, timeout=60, allow_redirects=False)
        if not initial_response:
            return False
        
        if initial_response.headers.get('location'):
            redirect_url = initial_response.headers['location']
            if '#access_token=' in redirect_url:
                dashboard_url = 'https://dashboard.teneo.pro/auth/verify'
                final_response = self.make_request('GET', dashboard_url, headers={'User-Agent': self.ua.random}, timeout=60)
                
                if final_response and 'Teneo Dashboard' in final_response.text:
                    log_message(self.current_num, self.total, "Email verification successful", "success")
                    return True
        
        log_message(self.current_num, self.total, "Email verification failed", "error")
        return False
    def login(self, email, password):
        log_message(self.current_num, self.total, "Attempting login...", "process")
        headers = {
            'accept': 'application/json, text/plain, */*',
            'content-type': 'application/json',
            'x-api-key': 'OwAG3kib1ivOJG4Y0OCZ8lJETa6ypvsDtGmdhcjA',
            'user-agent': self.ua.random,
            'Origin': 'https://dashboard.teneo.pro',
            'Referer': 'https://dashboard.teneo.pro/'
        }
        
        login_data = {
            "email": email,
            "password": password
        }
        
        response = self.make_request('POST', 'https://auth.teneo.pro/api/login', headers=headers, json=login_data, timeout=120)
                                   
        if not response:
            return {}
            
        result = response.json()
        
        if "access_token" in result:
            log_message(self.current_num, self.total, "Login successful", "success")
        else:
            log_message(self.current_num, self.total, "Login failed", "error")
        return result

    def link_wallet(self, access_token, email):
        log_message(self.current_num, self.total, "Generating wallet and linking...", "process")
        
        wallet = generate_ethereum_wallet()
        
        message = f"Permanently link wallet to Teneo account: {email} This can only be done once."
        signature = create_wallet_signature(wallet, message)
        
        
        headers = {
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Authorization': f'Bearer {access_token}',
            'Connection': 'keep-alive',
            'Content-Type': 'application/json',
            'Origin': 'https://dashboard.teneo.pro',
            'Referer': 'https://dashboard.teneo.pro/',
            'User-Agent': self.ua.random,
            'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"'
        }
        
        if not signature.startswith('0x'):
            signature = '0x' + signature
        
        link_data = {
            "address": wallet['address'],
            "signature": signature,
            "message": message
        }
        
        try:
            response = self.make_request('POST', 'https://api.teneo.pro/api/users/link-wallet', headers=headers, json=link_data, timeout=60)
            
            if not response:
                return None
                
            result = response.json()

            if result.get("success"):
                log_message(self.current_num, self.total, f"{result.get('message')}: {Fore.MAGENTA}{wallet['address']}{Fore.RESET}", "success")
                return wallet
            else:
                log_message(self.current_num, self.total, f"{result.get('message', 'Unknown error')}", "error")
                return None
                
        except Exception as e:
            log_message(self.current_num, self.total, f"Error linking wallet: {str(e)}", "error")
            return None
        
    def connect_websocket(self, access_token):
        log_message(self.current_num, self.total, "Waiting for activation...", "process")
        ws_url = f"wss://secure.ws.teneo.pro/websocket?accessToken={access_token}&version=v0.2"
        
        while True:
            try:
                ws = activation.create_connection(
                    ws_url,
                    header={
                        'Host': 'secure.ws.teneo.pro',
                        'Upgrade': 'websocket', 
                        'Connection': 'upgrade',
                        'Origin': 'chrome-extension://emcclcoaglgcpoognfiggmhnhgabppkm',
                        'User-Agent': self.ua.random
                    },
                    proxy=self.proxy if self.proxy else None,
                    timeout=120
                )
                
                while True:
                    ping_message = json.dumps({"type": "PING"})
                    ws.send(ping_message)
                    
                    response = ws.recv()
                    response_data = json.loads(response)
                    
                    if "message" in response_data and response_data["message"] == "Connected successfully":
                        ws.close()
                        log_message(self.current_num, self.total, "Activation successful", "success")
                        return True
                    
            except Exception as e:
                log_message(self.current_num, self.total, f"Activation error. Retrying, just wait...", "warning")
                continue
        
    def check_user_onboarded(self, access_token):
        if not self.connect_websocket(access_token):
            log_message(self.current_num, self.total, "Failed to activate", "error")
            return False
            
        log_message(self.current_num, self.total, "Checking account activate status...", "process")
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Authorization': f'Bearer {access_token}',
            'Connection': 'keep-alive',
            'Origin': 'https://dashboard.teneo.pro',
            'Referer': 'https://dashboard.teneo.pro/',
            'User-Agent': self.ua.random
        }
        
        max_attempts = 5
        for attempt in range(max_attempts):
            response = self.make_request('GET', 'https://api.teneo.pro/api/users/user-onboarded', headers=headers, timeout=60)
            
            if not response:
                continue
                
            data = response.json()
            if data.get('success') == True:
                log_message(self.current_num, self.total, "Account Activated! But still PENDING", "success")
                log_message(self.current_num, self.total, f"{Fore.LIGHTYELLOW_EX}IMPORTANT: Run accounts with teneo-bot until 100HB for SUCCESS referral{Fore.RESET}", "success")
                return True
                
            log_message(self.current_num, self.total, f"User not yet activated, Please wait...", "warning")
            
        log_message(self.current_num, self.total, "Failed to verify user activation", "error")
        return False

    def create_account(self, current_num, total):
        self.current_num = current_num
        self.total = total
        
        domain, email, password = self.generate_valid_credentials() 
        if not email:
            return None, "Could not generate valid credentials after multiple attempts"

        register_response = self.register_account(email, password)
        if register_response.get("role") != "authenticated":
            return None, "Registration failed"

        verification_url = self.get_verification_link(email, domain)
        if not verification_url:
            return None, "Could not get verification link"

        if not self.verify_email(verification_url):
            return None, "Email verification failed"

        login_response = self.login(email, password)
        if "access_token" not in login_response:
            return None, "Login failed"
            
        wallet = self.link_wallet(login_response["access_token"], email) 
        if not wallet:
            return None, "Wallet linking failed"
        
        if not self.check_user_onboarded(login_response["access_token"]):
            return None, "Account active validation failed"

        return {
            "email": email,
            "password": password,
            "access_token": login_response["access_token"],
            "wallet_private_key": wallet['private_key'],
            "wallet_address": wallet['address']
        }, "Success"

def main():
    banner = f"""
{Fore.LIGHTCYAN_EX}╔═══════════════════════════════════════════╗
║           Teneo Auto Referral             ║
║           Author: Nofan Rambe             ║
╚═══════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)    
    
    ref_code = input(f"{Fore.LIGHTYELLOW_EX}Enter referral code: {Fore.RESET}")
    count = int(input(f"{Fore.LIGHTYELLOW_EX}How many referrals?: {Fore.RESET}"))
    
    proxies = load_proxies()
    
    successful = 0
    
    with open("accounts.txt", "a") as f:
        for i in range(count):
            print(f"{Fore.LIGHTWHITE_EX}{'-'*85}")
            log_message(i+1, count, "Starting new referral process", "debug")

            current_proxy = get_random_proxy(proxies) if proxies else None
            generator = TeneoAutoref(ref_code, proxy=current_proxy)
            account, message = generator.create_account(i+1, count)
            
            if account:
                with open("accounts.txt", "a") as f:
                    f.write(f"Email: {account['email']}\n")
                    f.write(f"Password: {account['password']}\n")
                    f.write(f"Token: {account['access_token']}\n")
                    f.write(f"Wallet Private Key: {account['wallet_private_key']}\n")
                    f.write(f"Wallet Address: {account['wallet_address']}\n")
                    f.write(f"Points: 51000\n")
                    f.write("-" * 85 + "\n")
                    f.flush()
                successful += 1
                log_message(i+1, count, "Account created successfully!", "debug")
                log_message(i+1, count, f"Email: {account['email']}", "success")
                log_message(i+1, count, f"Password: {account['password']}", "success")
                log_message(i+1, count, f"Wallet Address: {account['wallet_address']}", "success")
                log_message(i+1, count, f"Points: 51000", "success")
                log_message(i+1, count, f"{Fore.LIGHTRED_EX}Link Bot: https://github.com/im-hanzou/teneo-bot{Fore.RESET}", "success") 
                log_message(i+1, count, f"{Fore.LIGHTRED_EX}Please ensure that all successfully referred accounts run teneo-bot{Fore.RESET}", "success")  
            else:
                log_message(i+1, count, f"Failed: {message}", "error")
                if generator.proxy:
                    log_message(i+1, count, f"Failed proxy: {generator.proxy}", "error")
    
    print(f"{Fore.MAGENTA}\n[*] Process completed!{Fore.RESET}")
    print(f"{Fore.GREEN}[*] Successfully created {successful} out of {count} accounts{Fore.RESET}")
    print(f"{Fore.MAGENTA}[*] Results saved in accounts.txt{Fore.RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.LIGHTYELLOW_EX}Process interrupted by user.")
