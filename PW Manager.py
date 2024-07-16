import os
import json
import string
import random
import base64
import hashlib
import PySimpleGUI as sg
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# File name constants
MASTER_PASSWORD_FILE = "master_password_hash.txt"
PASSWORDS_FILE = "passwords.json"


class PasswordManager:
    def __init__(self, master_password):
        salt = b'\x00' * 16
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password))
        self.cipher_suite = Fernet(key)
        if not os.path.exists(PASSWORDS_FILE):
            with open(PASSWORDS_FILE, "w") as file:
                json.dump({}, file)

    def check_master_password(self, master_password):
        if os.path.exists(MASTER_PASSWORD_FILE):
            with open(MASTER_PASSWORD_FILE, 'r') as file:
                stored_hash = file.readline().strip()
            # Hash entered password
            entered_hash = hashlib.sha256(master_password).hexdigest()
            return entered_hash == stored_hash
        else:
            return False

    def set_master_password(self, master_password):
        # Hash the master password
        hashed_password = hashlib.sha256(master_password).hexdigest()
        with open(MASTER_PASSWORD_FILE, 'w') as file:
            file.write(hashed_password)

    def generate_password(self, length=12, uppercase=True, lowercase=True, numbers=True, symbols=True):
        chars = ''
        if uppercase:
            chars += string.ascii_uppercase
        if lowercase:
            chars += string.ascii_lowercase
        if numbers:
            chars += string.digits
        if symbols:
            chars += string.punctuation
        return ''.join(random.choice(chars) for _ in range(length))

    def save_password(self, service, username, password, overwrite=False):
        try:
            with open(PASSWORDS_FILE, "r") as file:
                data = json.load(file)
        except json.JSONDecodeError:
            data = {}

        # If service exists, check for user
        if service in data:
            if username in data[service]:
                if not overwrite:
                    return 2  # User already exists for the service
            # Either user does not exist or overwrite is True
            data[service][username] = {
                "password": self.cipher_suite.encrypt(password.encode()).decode()
            }
        else:
            # If service does not exist, create new service and user
            data[service] = {
                username: {
                    "password": self.cipher_suite.encrypt(password.encode()).decode()
                }
            }

        with open(PASSWORDS_FILE, "w") as file:
            json.dump(data, file, indent=4)

        return 1  # Password saved successfully



    def load_password(self, service, username):
        try:
            with open(PASSWORDS_FILE, "r") as file:
                data = json.load(file)
        except json.JSONDecodeError:
            data = {}

        if service not in data or username not in data[service]:
            return None

        try:
            decrypted_data = {
                "password": self.cipher_suite.decrypt(data[service][username]["password"].encode()).decode()
            }
        except Exception as e:
            print(f"An error occurred while decrypting: {e}")
            return None

        return decrypted_data



class PasswordManagerApp:
    def __init__(self, manager):
        self.manager = manager
        self.layout = [
            [sg.Text("Service", size=(10, 1)), sg.InputText(key='-SERVICE-', size=(20, 1))],
            [sg.Text("Username", size=(10, 1)), sg.InputText(key='-USERNAME-', size=(20, 1))],
            [sg.Text("Password", size=(10, 1)), sg.InputText(key='-PASSWORD-', size=(20, 1), password_char='*')],
            [sg.Text('Password Length', size=(10, 1)), sg.Slider((8, 50), default_value=12, orientation='h', size=(15, 15), key='-LENGTH-')],
            [sg.Checkbox('Uppercase', default=True, key='-UPPERCASE-'), sg.Checkbox('Lowercase', default=True, key='-LOWERCASE-'), sg.Checkbox('Numbers', default=True, key='-NUMBERS-'), sg.Checkbox('Symbols', default=True, key='-SYMBOLS-')],
            [sg.Button("Generate Password"), sg.Button("Save Password"), sg.Button("Load Password"), sg.Button("Copy Password")],
            [sg.Output(size=(60, 10))],
            [sg.Button("User Manual")]
        ]

        self.window = sg.Window("Password Manager", self.layout)

    def user_manual(self):
        manual_text = """
        Password Manager Manual:
        
        - Generate Password: Click this button to generate a random password based on the specified settings.
        
        Note: Checkboxes are only for generating passwords.
        
        - Save Password: Enter the service name, username, and password in their respective fields, then click this button to save the password.
        
        - Load Password: Enter the service name and username in their respective fields, then click this button to load the password for the specified service and username.
        
        - Copy Password: Click this button to copy the password currently displayed in the password field to the clipboard.
        
        Note: Password field needs to be empty in order to load a password, an appropriate message will be displayed.
        """
        sg.popup("Password Manager Manual", manual_text)

    def generate_password(self, length, uppercase, lowercase, numbers, symbols):
        # If all checkboxes are unselected, force lowercase to be True
        if not (uppercase or lowercase or numbers or symbols):
            sg.popup("You must select at least one checkbox")
            return
        password = self.manager.generate_password(length, uppercase, lowercase, numbers, symbols)
        self.window['-PASSWORD-'].update(password)
        print("Password generated successfully.")

    def save_password(self, service, username, password):
        result = self.manager.save_password(service, username, password)
        if result == 1:
            print("Password saved successfully.")
        elif result == 2:
            popup_event = sg.popup_yes_no(f"A password for '{service}' and user '{username}' already exists. Do you want to overwrite it?")
            if popup_event == 'Yes':
                self.manager.save_password(service, username, password, overwrite=True)
                print("Password saved successfully.")


    def load_password(self, service, username):
        entered_password = self.window['-PASSWORD-'].get()
        data = self.manager.load_password(service, username)
        if data:
            if entered_password == '':
                self.window['-PASSWORD-'].update(data['password'])
                print("Password loaded successfully.")
            else:
                print("Password field needs to be empty in order to load a password.")
        else:
            print("No password found for this service and user or an error occurred.")


    def copy_password(self, password):
        if password:
            sg.clipboard_set(password)
            print("Password copied to clipboard.")
        else:
            print("No password available to copy.")


    def run(self):
        while True:
            event, values = self.window.read()
            if event == sg.WINDOW_CLOSED:
                break
            elif event == 'Generate Password':
                self.generate_password(int(values['-LENGTH-']), values['-UPPERCASE-'], values['-LOWERCASE-'], values['-NUMBERS-'], values['-SYMBOLS-'])
            elif event == 'Save Password':
                self.save_password(values['-SERVICE-'], values['-USERNAME-'], values['-PASSWORD-'])
            elif event == 'Load Password':
                self.load_password(values['-SERVICE-'], values['-USERNAME-'])
            elif event == 'Copy Password':
                self.copy_password(values['-PASSWORD-'])
            elif event == 'User Manual':
                self.user_manual()

        self.window.close()


if not os.path.exists(MASTER_PASSWORD_FILE):
    master_password = getpass("Setup your master password: ").encode()  # Use getpass to hide input
    manager = PasswordManager(master_password)
    manager.set_master_password(master_password)
else:
    while True:
        master_password = getpass("Enter your master password: ").encode()
        manager = PasswordManager(master_password)
        if manager.check_master_password(master_password):
            break
        else:
            print("Invalid master password. Please try again.")

app = PasswordManagerApp(manager)
app.run()
