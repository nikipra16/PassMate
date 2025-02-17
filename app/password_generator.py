import math
import secrets  # For secure random generation
import string   # For character sets
from collections import Counter


def load_word_list(filename):
    with open(filename, 'r') as file:
        return set(line.strip().lower() for line in file)

#common words to avoid
word_set = load_word_list("500-worst-passwords.txt")

allowed_punctuation = r"~!@#$%^&*()-=_+\[{]}"

# generates a password
def generate_password(length):
    if length < 8:
        raise ValueError("Password length must be at least 8!")

    all_chars = string.ascii_uppercase + string.ascii_lowercase + string.digits + allowed_punctuation

    while True:
        # Create password with at least one of each required character type
        password_chars = [
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.digits),
            secrets.choice(allowed_punctuation)
        ]

        while len(password_chars) < length:
            password_chars.append(secrets.choice(all_chars))

        secrets.SystemRandom().shuffle(password_chars)
        password = "".join(password_chars)

        # Check if the password contains any forbidden words
        if not any(word in password for word in word_set):
            return password
        else:

            continue

# Function to calculate shannon entropy
# def calculate_shannon_entropy(data):
#     n = len(data)
#     counter = Counter(data)
#     entropy = 0
#     for count in counter.values():
#         p = count / n
#         entropy -= p * math.log2(p)
#     return entropy

# calculates entropy for a particular password
# resource: https://www.omnicalculator.com/other/password-entropy
def calculate_entropy(password):
    pool_sizes = {
        "digits": 10,
        "lowercase": 26,
        "uppercase": 26,
        "special": 32  # Special characters (typical U.S. keyboard)
    }
    R = 0
    if any(char.isdigit() for char in password):
        R += pool_sizes["digits"]
    if any(char.islower() for char in password):
        R += pool_sizes["lowercase"]
    if any(char.isupper() for char in password):
        R += pool_sizes["uppercase"]
    if any(char in allowed_punctuation
           for char in password):
        R += pool_sizes["special"]

    L = len(password)

    E = L * math.log2(R)

    return E

# Function to test if the generated password distribution is random ( used ChatGpt)
def test_randomness(passwords):
    all_chars = ''.join(passwords)

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

    if any(word in password for word in word_set):
        errors.append("Password must not contain common words!!!")

    entropy = calculate_entropy(password)
    print(f"Password Entropy: {entropy:.2f} bits")

    if errors:
        return False, errors
    return True, []



if __name__ == "__main__":
    # passwords = [generate_password(12) for _ in range(10000)]  # Generate 1000 passwords
    # test_randomness(passwords)
    action = input("Do you want to generate a password? (y/n): ").strip().lower()

    if action == "y":
        while True:
            try:
                length = int(input("Enter the length of the password (minimum 8, maximum 100): ").strip())
                if length < 8 or (length > 100):
                    print("Password length must be at least 8 or at most 100. Please enter a valid number.")
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