from cryptography.fernet import Fernet

# Generate a consistent encryption key (only once)
key = Fernet.generate_key()
cipher = Fernet(key)
