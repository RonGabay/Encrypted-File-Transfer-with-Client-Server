# Secure File Transfer with Client-Server Architecture (C++/Python)
This project tackles secure file transfer, implementing a robust system with encryption and error handling.

# Project Overview
Clients can securely upload files to a server using features like:

Client-Initiated Communication:
Clients establish connections, exchange encryption keys, and upload encrypted files.

Encrypted Transfers:
AES encryption with client-provided public keys ensures data privacy.

File Verification:
Checksums (CRC) on both client and server sides guarantee file integrity.

Reliable Delivery:
Automatic retries handle failed file transfers (up to 3 attempts).

# Programming Languages:
Server-Side: Python (version 3.11.4)
Client-Side: C++
