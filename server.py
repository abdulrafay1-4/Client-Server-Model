import socket
import hashlib
import secrets
import os
import re
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class Client:
    def __init__(self):
        self.creds_file = "creds.txt"
        self.xor_key = 5
        
    def xor_encrypt_decrypt(self, data):
        result = ''.join([chr(ord(char) ^ self.xor_key) for char in data])
        return result

    def encrypt_file(self):
        with open(self.creds_file, "r") as file:
            data = file.read()

        encrypted_data = self.xor_encrypt_decrypt(data)
        with open(self.creds_file, "w") as file:
            file.write(encrypted_data)

    def decrypt_file(self):
        with open(self.creds_file, "r") as file:
            encrypted_data = file.read()

        decrypted_data = self.xor_encrypt_decrypt(encrypted_data)
        with open(self.creds_file, "w") as file:
            file.write(decrypted_data)
            
    def verify_credentials(self, username, password):
        # decrypt the credentials file first
        self.decrypt_file()
        with open(self.creds_file, "r") as file:
            for line in file:
                if username in line:
                    _, _, stored_hash, stored_salt = line.split(",")
                    
                    stored_password_hash = stored_hash.split(":")[1]
                    stored_salt = stored_salt.split(":")[1]
                    
                    salt = bytes.fromhex(stored_salt)
                    
                    to_hash = password.encode() + salt
                    hash_object = hashlib.sha256(to_hash)
                    hash_hex = hash_object.hexdigest()
                    # before returning, credentials file ko dobara encrypt kar dena
                    if hash_hex == stored_password_hash:
                        self.encrypt_file()
                        return True
        self.encrypt_file()
        return False
    
    def change_password(self, uName, new_password):
        self.decrypt_file()
        with open(self.creds_file, "r") as file:
            lines = file.readlines()
        with open(self.creds_file, "w") as file:
            for line in lines:
                if uName in line:
                    email, username, _, salt = line.split(",")
                    salt = bytes.fromhex(salt.split(":")[1])
                    to_hash = new_password.encode() + salt
                    hash_object = hashlib.sha256(to_hash)
                    hash_hex = hash_object.hexdigest()
                    file.write(f"email:{email},username:{username},password:{hash_hex},salt:{salt.hex()}\n")
                else:
                    file.write(line)
        self.encrypt_file()
        
    def change_username(self, old_username, new_username):
        self.decrypt_file()
        with open(self.creds_file, "r") as file:
            lines = file.readlines()
        with open(self.creds_file, "w") as file:
            for line in lines:
                if old_username in line:
                    email, _, password, salt = line.split(",")
                    file.write(f"email:{email},username:{new_username},password:{password},salt:{salt}")
                else:
                    file.write(line)
        self.encrypt_file()
        
    def store_credentials(self, email, username, password_hash, salt):
        self.decrypt_file()
        with open(self.creds_file, "a") as file:
            file.write(f"email:{email},username:{username},password:{password_hash},salt:{salt.hex()}\n")
        self.encrypt_file()
        
    def check_unique_username(self, username):
        self.decrypt_file()
        with open(self.creds_file, "r") as file:
            for line in file:
                if username in line:
                    self.encrypt_file()
                    return False
        self.encrypt_file()
        return True


    def check_valid_email(self,email):
        if re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return True
        else:
            return False

    def check_unique_email(self, email):
        self.decrypt_file()
        with open(self.creds_file, "r") as file:
            for line in file:
                if email in line:
                    self.encrypt_file()
                    return False
        self.encrypt_file()
        return True

    def hash_password(self, password):
        # Generate a salt and hash password
        salt = secrets.token_bytes(32)
        to_hash = password.encode() + salt
        hash_object = hashlib.sha256(to_hash)
        hash_hex = hash_object.hexdigest()
        return hash_hex, salt
 
def Diffie_Hellman():
    p = 23
    g = 5
    b = secrets.randbelow(p-2)
    B = (g**b) % p
    
    return p, b, B 
 
def AES_Encryption(username, key, message):
    AESkey = (username + str(key)).encode('utf-8')
    AESkey = AESkey[:16].ljust(16, b'\0')

    iv = get_random_bytes(AES.block_size)
    
    cipher = AES.new(AESkey, AES.MODE_CBC, iv)
    encrypted_message = iv + cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    
    return encrypted_message

def AES_Decryption(username, key, encrypted_message):
    AESkey = (username + str(key)).encode('utf-8')
    AESkey = AESkey[:16].ljust(16, b'\0')
    
    iv = encrypted_message[:AES.block_size]

    cipher = AES.new(AESkey, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(encrypted_message[AES.block_size:]), AES.block_size)
    
    return decrypted_message.decode('utf-8')

#!SECTION - CLIENT - SERVER COMMUNICATION
def handle_client(client_socket):
    #LINK - DIFFIE HELLMAN KEY EXCHANGE
    
    verifyLink = False
    
    # reveive p and g from the client
    data = client_socket.recv(256).decode('utf-8')
    # receive A from the client
    _, A = data.split(":")
    A = int(A)
    p, b, B = Diffie_Hellman()
    client_socket.send(f"Server's Public Key:{B}".encode('utf-8'))
    
    # calculate the shared secret key
    K = (A**b)%p
    print("\n\n\tThe client and server have decided on shared secret key\n\n") 
    
    action = client_socket.recv(256).decode('utf-8')
    client = Client()
    if action == "Logging In":
        client_socket.send("Logging In User".encode('utf-8'))
        count = 1
        while count <= 3:
            data = client_socket.recv(256).decode('utf-8')
            _, username, _, encryped_password = data.split(":")
            encrypted_password = base64.b64decode(encryped_password)
            password = AES_Decryption(username, K, encrypted_password)

            if client.verify_credentials(username, password):
                verifyLink = True
                client_socket.send("Valid User".encode('utf-8'))
                break
            else:
                count += 1
                if count <= 3:
                    client_socket.send("Invalid User".encode('utf-8'))
                else:
                    client_socket.send("Max Attempts Exceeded".encode('utf-8'))
                    break
    
    elif action == "User Registration":
        client_socket.send("Registering User".encode('utf-8'))
        count = 1
        while count <= 3:
            data = client_socket.recv(256).decode('utf-8')
            _, username, _, email, _, encrypted_password = data.split(":")
            encrypted_password = base64.b64decode(encrypted_password)
            password = AES_Decryption(username, K, encrypted_password)
            if not client.check_valid_email(email):
                client_socket.send("Invalid Email".encode('utf-8'))
                count += 1
                continue
            if not client.check_unique_email(email):
                client_socket.send("Email Already Exists".encode('utf-8'))
                count += 1
                continue
            if not client.check_unique_username(username):
                client_socket.send("Username Already Exists".encode('utf-8'))
                count += 1
                continue
            
            # Successful registration
            password_hash, salt = client.hash_password(password)
            client.store_credentials(email, username, password_hash, salt)
            verifyLink = True
            client_socket.send("User Registered".encode('utf-8'))
            break
    
    
    if verifyLink == False:
        print("Login / Registration Failed ! Try Again Later")
        return
    
    action = client_socket.recv(256).decode('utf-8')
    
    #NOTE - changing the password of the user
    if action == "Change Password":
        data = client_socket.recv(256).decode('utf-8')
        if "Invalid" in data:
            print("Invalid Password was entered! Password Change Failed")
            return
        try:
            _, username, _, new_encrypted_password = data.split(":")
            new_encrypted_password = base64.b64decode(new_encrypted_password)
            new_password = AES_Decryption(username, K, new_encrypted_password)
            if client.verify_credentials(username, password):
                client.change_password(username, new_password)
                print(f"Password for user {username} has been successfully changed.")
                password = new_password
            else:
                client_socket.send("Invalid credentials".encode('utf-8'))
        except Exception as e:
            print(f"Error while changing password: {e}")
            client_socket.send("Error during password change".encode('utf-8'))

    elif action == "Change Username":
        data = client_socket.recv(256).decode('utf-8')
        _, old_username, _, new_username = data.split(":")
        
        if client.check_unique_username(new_username):
            client.change_username(old_username, new_username)
            username = new_username
            client_socket.send("Username Changed".encode('utf-8'))
        else:
            client_socket.send("Username Already Exists".encode('utf-8'))

    else:
        print("Client chose to continue without any changes.")  
        
    #!SECTION - CLIENT - SERVER COMMUNICATION
    while True:
        # receive message from the client
        buf = client_socket.recv(256).decode('utf-8')
        buf = base64.b64decode(buf)
        buf = AES_Decryption(username, K, buf)
        # if client sends "exit", close the connection
        if buf == "exit":
            print("Client disconnected.")
            break

        print("Client:", buf)

        # send a response back to the client
        response = input("Enter a message: ")
        message = "Server: " + response
        message = AES_Encryption(username, K, message)
        message = base64.b64encode(message).decode('utf-8')
        client_socket.send(message.encode('utf-8'))

    client_socket.close()




def main():
    print("\n\t>>>>>>>>>> FAST NUCES University Chat Server <<<<<<<<<<\n\n")
    print("\n\t>>>>>>>>>>>>>>>>>>>>>> RULES <<<<<<<<<<<<<<<<<<<<<<<<<<\n\n")
    print("\t1. You can only change your password 3 times\n")
    print("\t2. You can only change your username once\n")
    print("\t3. You can only change your password if you know your old password\n")
    print("\t4. You have 3 attempts to login\n")
    print("\t7. You have 3 attempts to register\n")
    print("\t5. You can only register if your email is valid and unique\n")
    print("\t6. You can only register if your username is unique\n")
    print("\t7. You can only change your username if the new username is unique\n")

    # create the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # define the server address
    server_address = ('', 8080)

    # bind the socket to the specified IP and port
    server_socket.bind(server_address)
    server_socket.listen(5)

    while True:
        # accept incoming connections
        client_socket, client_address = server_socket.accept()

        # create a new process to handle the client
        pid = os.fork()
        if pid == -1:
            print("Error! Unable to fork process.")
        elif pid == 0:
            # child process handles the client
            handle_client(client_socket)
            os._exit(0)
        else:
            # parent process continues accepting clients
            client_socket.close()

if __name__ == "__main__":
    main()