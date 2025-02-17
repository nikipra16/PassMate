import math
import secrets  # For secure random generation
import string   # For character sets
from collections import Counter

# generates a password
def generate_password(length=8,):
    allowed_punctuation = "!@#$%^&*()"
    if length < 8:
        raise ValueError("Password length must be at least 8!")

    all_chars = string.ascii_uppercase + string.ascii_lowercase + string.digits + allowed_punctuation

    # atleast one of each
    password_chars = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(allowed_punctuation)
    ]

    while len(password_chars) < length:
        password_chars.append(secrets.choice(all_chars))

    secrets.SystemRandom().shuffle(password_chars)
    return ''.join(password_chars)


# validates a generated password
def is_valid_password(password):
    allowed_punctuation = "!@#$%^&*()"
    if len(password) < 8:
        return False

    if (any(c.isupper() for c in password) and
            any(c.islower() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in allowed_punctuation for c in password)):
        return True
    return False


if __name__ == "__main__":
    action = input("Do you want to generate a password? (y/n): ").strip().lower()

    if action == "y":
        length = int(input("Enter the length of the password (minimum 8): ").strip())
        if length < 8:
            print("Password length must be at least 8.")
        else:
            generated_password = generate_password(length)
            print(f"Generated Password: {generated_password}")

    elif action == "n":
        print("Okay, no password generated.")

    else:
        print("Invalid input. Please enter 'y' for yes or 'n' for no.")

    validate_action = input("Do you want to validate a password? (y/n): ").strip().lower()
    if validate_action == "y":
        password_to_validate = input("Enter the password to validate: ").strip()
        if is_valid_password(password_to_validate):
            print("Password is valid.")
        else:
            print("Password is invalid.")
    elif validate_action == "n":
        print("Okay, no validation done.")
    else:
        print("Invalid input. Please enter 'y' for yes or 'n' for no.")