from werkzeug.security import generate_password_hash

# Define your password
password = "Karnal.123"

# Hash the password
password_hash = generate_password_hash(password)

# Print the hashed password
print("Hashed Password:", password_hash)
