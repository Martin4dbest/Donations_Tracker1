from werkzeug.security import generate_password_hash

# User's plaintext password
password = "2019@Harmony"

# Generate the hashed password
hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

# Print the hashed password
print(f"Hashed password: {hashed_password}")
