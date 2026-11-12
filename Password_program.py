"""
CYB3038 Project - Milestone 4: First Draft Code
Author: Jeffrey Lemos
Description: Password program implementing policy validation, salt generation, 
hashing, and account authentication lockout.
"""

import hashlib
import json
import os

DB_FILE = "users_db.json"


# Helper Database Functions 
def load_database():
    """Loads stored user credentials from a local JSON file."""
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}


def save_to_database(username, hashed_pw, salt):
    """Saves user record to the local JSON file."""
    db = load_database()
    db[username] = {"hashed_pw": hashed_pw, "salt": salt}
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=4)


def user_exists(username):
    """Checks if a username already exists in the database."""
    db = load_database()
    return username in db


def retrieve_user_data(username):
    """Retrieves stored hash and salt for a given user."""
    db = load_database()
    if username in db:
        return db[username]["hashed_pw"], db[username]["salt"]
    return None, None


#  1. Password Policy Validation (Milestone 1 Alignment) 
def validate_password_policy(password):
    """Validates the password against USNA-derived policy guidelines:

    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."

    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter."

    if not any(char.islower() for char in password):
        return False, "Password must contain at least one lowercase letter."

    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one number."

    special_chars = "!@#$%^&*()_+-=[]{}|;:'\",.<>?/\\"
    if not any(char in special_chars for char in password):
        return False, "Password must contain at least one special character."

    return True, "Password meets policy guidelines."


#  2. Cryptographic Functions 
def generate_random_salt():
    """Generates a secure random 16-byte hex salt."""
    return os.urandom(16).hex()


def hash_password(password, salt):
    """Hashes the password combined with the salt.

    Note: Can use SHA-256 or swap to a legacy hash researched in Milestone 2
    (e.g., hashlib.md5 or hashlib.sha1) if required by specific testing.
    """
    combined_string = password + salt
    return hashlib.sha256(combined_string.encode("utf-8")).hexdigest()


#  3. Main Program Loop 
def main():
    print("=== Account Setup ===")
    account_created = False

    # Account Creation Loop
    while not account_created:
        username = input("Enter username: ").strip()

        if not username:
            print("Username cannot be empty. Please try again.")
            continue

        if user_exists(username):
            print("Username already exists. Please choose a different username.")
            continue

        new_password = input("Enter new password: ")

        is_valid, message = validate_password_policy(new_password)

        if is_valid:
            generated_salt = generate_random_salt()
            hashed_pw = hash_password(new_password, generated_salt)
            save_to_database(username, hashed_pw, generated_salt)
            print("Account successfully created!\n")
            account_created = True
        else:
            print(f"Policy Error: {message}")
            print("Please try again.\n")

    # User Login Loop
    print("=== User Login ===")
    max_attempts = 3
    attempts = 0
    logged_in = False

    while attempts < max_attempts and not logged_in:
        input_username = input("Enter username: ").strip()
        input_password = input("Enter password: ")

        if user_exists(input_username):
            stored_hash, stored_salt = retrieve_user_data(input_username)
            input_hash = hash_password(input_password, stored_salt)

            if input_hash == stored_hash:
                print("Access Granted. Welcome!")
                logged_in = True
            else:
                attempts += 1
                remaining = max_attempts - attempts
                print(f"Invalid password. Remaining attempts: {remaining}\n")
        else:
            attempts += 1
            remaining = max_attempts - attempts
            print(f"Username not found. Remaining attempts: {remaining}\n")

    if not logged_in:
        print("Account locked due to too many failed attempts.")


if __name__ == "__main__":
    main()