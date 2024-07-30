
![images](https://github.com/user-attachments/assets/be8a834d-4753-4b3f-b19e-c07fdf611318)



## Overview
The XOR Encryptor application provides a method for encrypting and decrypting files using a combination of a key file and two separate passwords. This approach ensures a unique and secure encryption process, making it suitable for protecting sensitive data. However, users should be aware that this implementation, based on XOR encryption, does not inherently offer the same level of security as more advanced encryption standards like AES.

## Encrypting a File
To encrypt a file, the user must provide several inputs. First, the operation mode, indicated by 'e' for encryption, specifies the action to be performed. The user also needs to specify the input file, which is the path to the file that is to be encrypted. Additionally, a key file must be provided; this file contains the key data used in the XOR encryption process. Along with these, the user must enter two passwords: the first, known as the salt password, is used to derive a salt, ensuring that even if the same key and input file are used, the encryption result will differ. The second password, referred to as the nonce password, is used to derive a nonce (Number Used Once), which adds another layer of uniqueness to each encryption operation. The command to encrypt a file would look like this: ./xor e input_file key_file salt_password nonce_password.

## Decrypting a File
Decrypting a file follows a similar process but requires different input values. The operation mode should be set to 'd' for decryption. The user must again provide the input file, which in this case is the file that was previously encrypted. The key file used during the encryption must also be provided to ensure correct decryption. The same salt password and nonce password used during encryption must be used again for the decryption process to successfully regenerate the salt and nonce. The command to decrypt a file would be ./xor d input_file key_file salt_password nonce_password.

## How the Application Works
The XOR Encryptor leverages a combination of a key file and two passwords to perform encryption and decryption. Here’s a detailed breakdown of how these components interact and function within the application.

The key file is a critical element in the encryption process. It contains the data used in the XOR operation against the input file's data. For security and completeness, the key file must be at least as long as the input file to ensure every byte of the input file can be processed securely. The security of this key file is paramount; it must be protected and managed with strict access controls.

The application uses two passwords to enhance security: the salt password and the nonce password. The salt password is used to derive a cryptographic salt using a key derivation function (KDF), specifically PBKDF2 with HMAC-SHA256. The derived salt ensures that even if the same key and input file are used, the encrypted data will be different if the salt changes. This process introduces additional randomness, protecting against attacks that exploit predictable encryption outputs.

The nonce, derived from the nonce password and the salt, serves as a critical security feature. It ensures that each encryption operation is unique, even if the plaintext and key remain the same. The nonce is also derived using PBKDF2, linking it to both the nonce password and the salt. This setup prevents replay attacks and ensures that identical data does not always result in identical ciphertexts.

In the encryption process, after deriving the salt and nonce, the application reads data from the input file and the key file in chunks. The data from the input file is XORed with the corresponding data from the key file and the nonce, producing the encrypted output. This output is written to a temporary file, which then replaces the original input file. For decryption, the same process is followed in reverse, using the same key file and passwords to correctly recover the original data.

Security Considerations
While the XOR Encryptor's use of a key file and two passwords enhances security over basic XOR encryption, it is important to note that it does not provide the same level of security as more sophisticated encryption methods like AES. Users should employ strong, unique passwords for both the salt and nonce to ensure robust security. Additionally, the key file must be securely managed and protected, as it is crucial to the encryption and decryption processes.

