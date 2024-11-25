import bcrypt

def encrypt_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')  
def check_password(stored_hash: str, password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
if __name__ == "__main__":
    user_password = input("Enter a password to encrypt: ")
    
    encrypted_password = encrypt_password(user_password)
    print(f"Encrypted password: {encrypted_password}")
    
    password_to_check = input("Re-enter password to verify: ")
    if check_password(encrypted_password, password_to_check):
        print("Password .")
    else:
        print("Password does not match.")
