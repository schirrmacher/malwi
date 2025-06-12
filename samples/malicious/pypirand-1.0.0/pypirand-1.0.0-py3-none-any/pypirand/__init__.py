import random
import string

def generate_password(length=8):
    """Generate a random password of the specified length"""
    letters = string.ascii_letters
    digits = string.digits
    symbols = string.punctuation

    # Combine all the characters into a single string
    all_chars = letters + digits + symbols

    # Generate a password by choosing random characters from the string
    password = "".join(random.choice(all_chars) for i in range(length))

    return password
