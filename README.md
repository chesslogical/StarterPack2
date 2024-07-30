## Starter Pack 2

1- A nice Cryptographically Secure key maker. Generates a detailed report to prove it, too! 

2- Absurdly simple xor encryption. Used right, it functions as a OTP. 


3) The previous OTP app (2-) on steroids with enhanced security measures. It requires a key that is longer than the file to encrypt and 2 passwords. A cryptographic salt is made using a key derivation function (KDF), specifically PBKDF2 with HMAC-SHA256. The nonce, derived from the nonce password and the salt, serves as a critical security feature. It ensures that each encryption operation is unique, even if the plaintext and key remain the same. The nonce is also derived using PBKDF2, linking it to both the nonce password and the salt. This setup prevents replay attacks and ensures that identical data does not always result in identical ciphertexts.
