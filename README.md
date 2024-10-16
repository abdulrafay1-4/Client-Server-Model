# Secure Chat Client-Server Model

This project implements a secure communication system between a client and a server using Python. It utilizes the Diffie-Hellman key exchange for establishing a shared secret and AES-CBC mode for message encryption. The system also includes secure user authentication, with credentials stored in a hashed and salted format.

## Features
- **Diffie-Hellman Key Exchange**: Establishes a shared secret over an unsecured channel.
- **AES-CBC Encryption**: Encrypts messages exchanged between the client and server.
- **Secure User Authentication**: Credentials stored in a hashed and salted format to ensure security.

## Files
- **client.py**: Manages client-side operations, including sending and receiving encrypted messages.
- **server.py**: Handles server-side operations, receiving and processing encrypted messages from clients.
- **creds.txt**: Contains user credentials in a secure format for authentication.

## Setup

1. **Clone the repository**:
    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```

2. **Install Dependencies**:
   Ensure Python is installed and any required libraries (like `cryptography` and `socket`) are available.

3. **Run the Server**:
    ```bash
    python server.py
    ```

4. **Run the Client**:
    ```bash
    python client.py
    ```

## How It Works
1. The client connects to the server.
2. Both parties perform the Diffie-Hellman key exchange to compute a shared secret.
3. Messages are encrypted using AES-CBC with the shared secret, ensuring confidentiality during transmission.

## Credentials Management
- User credentials are stored in `creds.txt` in a hashed and salted format.
- Modify this file to manage user accounts, ensuring passwords are securely hashed.

## Security Considerations
- Keep the `creds.txt` file secure and avoid exposing it in public repositories.
- Use strong parameters for Diffie-Hellman and ensure the shared secret is managed securely.

## Future Improvements
- Enhance error handling and logging.
- Implement a more robust user authentication system.
- Consider adding features like message signing for integrity verification.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments
- [Python Documentation](https://docs.python.org/3/)
- [Cryptography Library](https://cryptography.io/en/latest/)
