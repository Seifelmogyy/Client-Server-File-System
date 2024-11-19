# Client-Server-File-System

This project implements a client-server application that allows users to sign up, log in, upload files, list files, and download files. The server ensures that each user has access to only their own files, with a separate folder for each user. The server adopted state of art security practices to ensure the confidentiality and the integrity of the Data.

## Features

- **User Authentication**: Users can sign up and log in securely.
- **File Management**: Users can upload, list, and download their files.
- **Personalized Folders**: Each user has their own folder, where they can only see and interact with their files.
- **Client-Server Architecture**: The application uses a client-server model to handle file operations.

## Security and Cryptography practices

This application incorporates the following security measures:

- **SSL Encryption**: All communication between the client and server is encrypted using SSL (Secure Socket Layer) to prevent eavesdropping and man-in-the-middle attacks.
- **Hashed Passwords**: User passwords are securely stored using a hashing algorithm (e.g., bcrypt or SHA-256), ensuring that passwords are never stored in plain text.
- **Diffie-Hellman Key Exchange**: The Diffie-Hellman protocol is used to securely exchange keys for AES 256-bit encryption, which is then used for encrypting and decrypting uploaded files, ensuring confidentiality and integrity.
- **AES 256-bit File Encryption**: Files are encrypted using AES (Advanced Encryption Standard) with a 256-bit key, providing strong encryption to protect files during storage and transfer.


## Installation

### Prerequisites

- Python 3.x
- MYSQL

### Set Up

1. Clone this repository to your local machine:

   ```bash
   git clone https://github.com/Seifelmogyy/Client-Server-File-System.git
   cd Client-Server-File-System
