import socket
import secrets
import base64
import getpass
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def create_socket():
    # create the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # setup an address
    server_address = ('localhost', 8080)
    sock.connect(server_address)
    return sock           


def login():
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    
    return username, password
    
def check_password_strength(password):
    if len(password) < 8:
        return False
    for char in password:
        if not char.isalnum():
            return False 
    return True 

def register():
    print("\n\t>>>>>>>>>>>>>>>>>>>>>> REGISTER <<<<<<<<<<<<<<<<<<<<<<<<<<\n\n")
    email = input("Enter your email: ")
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    
    return email, username, password        

def Diffie_Hellman():
    p = 23
    g = 5
    a = secrets.randbelow(p-2)
    A = (g**a) % p    
    return p, a, A

def AES_Encryption(username, key, message):
    AESkey = (username + str(key)).encode('utf-8')
    AESkey = AESkey[:16].ljust(16, b'\0')

    iv = get_random_bytes(AES.block_size)
    
    cipher = AES.new(AESkey, AES.MODE_CBC, iv)
    encrypted_message = iv + cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))  # Prepend IV to the encrypted message
    
    return encrypted_message

def AES_Decryption(username, key, encrypted_message):
    AESkey = (username + str(key)).encode('utf-8')
    AESkey = AESkey[:16].ljust(16, b'\0')
    
    iv = encrypted_message[:AES.block_size]
    cipher = AES.new(AESkey, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(encrypted_message[AES.block_size:]), AES.block_size)
    
    return decrypted_message.decode('utf-8')

def main():
    print("\n\t>>>>>>>>>> FAST NUCES University Chat Client <<<<<<<<<<\n\n")
    print("\n\t>>>>>>>>>>>>>>>>>>>>>> RULES <<<<<<<<<<<<<<<<<<<<<<<<<<\n\n")
    print("\t1. You can only change your password 3 times\n")
    print("\t2. You can only change your username once\n")
    print("\t3. You can only change your password if you know your old password\n")
    print("\t4. You have 3 attempts to login\n")
    print("\t7. You have 3 attempts to register\n")
    print("\t5. You can only register if your email is valid and unique\n")
    print("\t6. You can only register if your username is unique\n")
    print("\t7. You can only change your username if the new username is unique\n")
    print("8. Sending \"exit\" message to the server will disconnect chat")
    print("\nWelcome to the chat! Please create an account to start chatting")
    
    # Create socket and connect to the server
    sock = create_socket()
    
    print("\n\t>>>>>>>>>>>>>>>>>>>>>> Authorization <<<<<<<<<<<<<<<<<<<<<<<<<<\n\n")
    print(">>>>>>>>>>>>  1. LOGIN   <<<<<<<<<<<<<<<")
    print(">>>>>>>>>>>>  2. REGISTER   <<<<<<<<<<<<<<<")
    choice = input("\nChoose: ")
    #NOTE -  when the user has an account so chooses login
    if(choice == "1"):        
        #ANCHOR - DIFFIE HELLMAN KEY EXCHANGE
        # send p, g and A to the server
        
        p, a, A = Diffie_Hellman()
        sock.send(f"Client Public Key:{A}".encode('utf-8'))
        
        # receive B from the server
        data = sock.recv(256).decode('utf-8')
        _, B = data.split(":")
        
        B = int(B)
        K = (B**a)%p
        print("\n\n\tThe client and server have agreed on a shared secret key\n\n")
        
        sock.send("Logging In".encode('utf-8'))
        resp = sock.recv(256).decode('utf-8')
        
        if resp == "Logging In User":
            count = 1
            while count <= 3:
                username, password = login()
                encrypted_password = AES_Encryption(username, K, password)
                encrypted_password_b64 = base64.b64encode(encrypted_password).decode('utf-8')
                message = f"Username:{username}:Password:{encrypted_password_b64}"
                sock.send(message.encode('utf-8'))

                response = sock.recv(256).decode('utf-8')
                if response == "Valid User":
                    print(f"\n\tYou are now logged in as {username}\n")
                    break
                else:
                    count += 1
                    print("Invalid credentials. Please try again.")
            if count > 3:
                print("You have exceeded the maximum number of attempts")
                return
        else:
            print("Server is not ready to log in user")
            return
        
    #NOTE -  when the user registers a new account
    elif choice == "2":    
        #ANCHOR - DIFFIE HELLMAN KEY EXCHANGE
        # send p, g and A to the server
        
        p, a, A = Diffie_Hellman()
        sock.send(f"Client Public Key:{A}".encode('utf-8'))
        
        # receive B from the server
        data = sock.recv(256).decode('utf-8')
        _, B = data.split(":")
        
        B = int(B)
        K = (B**a)%p
        print("\n\n\tThe client and server have agreed on a shared secret key\n\n")
        
        sock.send("User Registration".encode('utf-8'))
        resp = sock.recv(256).decode('utf-8')
        
        if resp == "Registering User":
            count = 1
            while count <= 3:
                email, username, password = register()
                if not check_password_strength(password):
                    print("Password must be at least 8 characters long and contain only alphanumeric characters")
                    count += 1
                    continue
                encrypted_password = AES_Encryption(username, K, password)
                encrypted_password_b64 = base64.b64encode(encrypted_password).decode('utf-8')

                message = f"Username:{username}:Email:{email}:Password:{encrypted_password_b64}"
                sock.send(message.encode('utf-8'))

                response = sock.recv(256).decode('utf-8')
                if response == "User Registered":
                    print(f"\n\tYour account has been created. You are now logged in as {username}\n")
                    break
                else:
                    count += 1
                    print(response)
            if count > 3:
                print("You have exceeded the maximum number of attempts")
                return
        else:
            print("Server is not ready to register user")
            return    
                           
    else:
        print("Invalid choice")
        return
    
    print("\n\t>>>>>>>>>>>>>>>>>>>>>> OPTIONS <<<<<<<<<<<<<<<<<<<<<<<<<<\n\n")
    print(">>>>>>>>>>>>  1. Change Password   <<<<<<<<<<<<<<<")
    print(">>>>>>>>>>>>  2. Change Username   <<<<<<<<<<<<<<<")
    print(">>>>>>>>>>>> Press any Key to Continue <<<<<<<<<<<")
    choice = input("\nChoose: ")

    if choice == "1":
        c = 1
        old_pass = ""
        while old_pass != password and c <= 3:
            old_pass = input("Enter your old password: ")
            if old_pass != password:
                c += 1
                print("Invalid password! Try Again\n")
                continue
            else:
                break
        if c > 3:
            print("You have exceeded the maximum number of attempts")
            sock.send("Username:Invalid:Password:Invalid".encode('utf-8'))  # Notify server of failed attempts
            return
        sock.send("Change Password".encode('utf-8'))
        
        # Get new password
        c = 1
        while c <= 3:
            new_password = getpass.getpass("Enter new password: ")
            if not check_password_strength(new_password):
                print("Password must be at least 8 characters long and contain only alphanumeric characters")
                c += 1
                continue
            else:
                encrypted_password = AES_Encryption(username, K, new_password)
                encrypted_password_b64 = base64.b64encode(encrypted_password).decode('utf-8')
                message = f"Username:{username}:Password:{encrypted_password_b64}"
                sock.send(message.encode('utf-8'))
                print("\n\tYour password has been changed\n")
                password = new_password
                break
        if c > 3:
            sock.send("Username:Invalid:Password:Invalid".encode('utf-8'))  # Notify server of failed attempts
            print("Password was not changed")

    elif choice == "2":
        sock.send("Change Username".encode('utf-8'))
        new_username = input("Enter new username: ")
        message = f"Username:{username}:NewUsername:{new_username}"
        sock.send(message.encode('utf-8'))
        response = sock.recv(256).decode('utf-8')
        
        if response == "Username Changed":
            print(f"\n\tYour username has been changed to {new_username}\n")
            username = new_username
        elif response == "Username Already Exists":
            print(f"Username '{new_username}' already exists. Please try a different username.")
        else:
            print(f"Error: {response}")

    else:
        sock.send("No Change".encode('utf-8'))
        
    #!SECTION - CLIENT - SERVER COMMUNICATION

    while True:
        # Get user input and send it to the server
        message = input(f"{username}: ")
        enc_message = AES_Encryption(username, K, message)
        # Send the message to the server
        enc_message = base64.b64encode(enc_message).decode('utf-8')
        sock.send(enc_message.encode('utf-8'))

        # If the client sends "exit", terminate the chat
        if message == "exit":
            print("You disconnected from the chat.")
            break

        # receive response from server
        response = sock.recv(256).decode('utf-8')
        response = base64.b64decode(response)
        response = AES_Decryption(username, K, response)
        print(response)

    # Close the socket after communication
    sock.close()
    

if __name__ == "__main__":
    main()
