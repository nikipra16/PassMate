import math
import secrets  # For secure random generation
import string   # For character sets
from collections import Counter

# generates a password
def generate_password(length=8,):
    """
    Generates a secure password with at least:
    - One uppercase letter
    - One lowercase letter
    - One digit
    - One punctuation character (from the allowed set)
    """
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

# Function to calculate entropy
def calculate_entropy(data):
    n = len(data)
    counter = Counter(data)
    entropy = 0
    for count in counter.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy

# Function to test if the generated password is random ( used ChatGpt)
def test_randomness(passwords, expected_entropy=4.5):
    all_chars = ''.join(passwords)  # Join all passwords into a single string

    # Calculate entropy
    entropy = calculate_entropy(all_chars)
    print(f"Entropy of generated passwords: {entropy:.4f}")

    # Check if the entropy is within an expected range (higher entropy means more randomness)
    if entropy < expected_entropy:
        print("Warning: Low entropy! The passwords may not be sufficiently random.")
    else:
        print("The entropy is sufficient, the passwords seem random.")

    # Frequency check (optional)
    char_counts = Counter(all_chars)
    print("\nCharacter Frequencies:")
    for char, count in char_counts.items():
        print(f"{char}: {count}")

    # Additional check: Proportion of each character type should be approximately uniform
    total_chars = len(all_chars)
    for char, count in char_counts.items():
        proportion = count / total_chars
        print(f"Character '{char}' appears {proportion * 100:.2f}% of the time.")


# validates a generated password
def is_valid_password(password):
    allowed_punctuation = "!@#$%^&*()"
    errors = []

    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")

    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter.")

    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter.")

    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one digit.")

    if not any(c in allowed_punctuation for c in password):
        errors.append(f"Password must contain at least one special character from {allowed_punctuation}.")

    if errors:
        return False, errors
    return True, []


# Test the generator when running the script directly
if __name__ == "__main__":
    # passwords = [generate_password(8) for _ in range(1000)]  # Generate 1000 passwords
    # test_randomness(passwords)
    action = input("Do you want to generate a password? (y/n): ").strip().lower()

    if action == "y":
        while True:
            try:
                length = int(input("Enter the length of the password (minimum 8): ").strip())
                if length < 8:
                    print("Password length must be at least 8. Please enter a valid number.")
                else:
                    generated_password = generate_password(length)
                    print(f"Generated Password: {generated_password}")
                    break
            except ValueError:
                print("Invalid input. Please enter a valid number.")

    elif action == "n":
        print("Okay, no password generated.")

    else:
        print("Invalid input. Please enter 'y' for yes or 'n' for no.")

    validate_action = input("Do you want to validate a password? (y/n): ").strip().lower()
    if validate_action == "y":
        password = input("Enter the password to validate: ").strip()
        is_valid, errors = is_valid_password(password)
        if is_valid:
            print("Password is valid.")
        else:
            print("Password is not that safe. Here are the issues:")
            for error in errors:
                print(f"- {error}")
    elif validate_action == "n":
        print("Okay, no validation done.")
    else:
        print("Invalid input. Please enter 'y' for yes or 'n' for no.")