# Asymmetric Encryption in Python
* Primary references
  * https://cryptography.io/en/latest/
  * https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
  * https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/
* Practicing with more cryptography in Python. RSA key pairs can be created, saved, and used to encrypt or decrypt files. After creation, keys are saved to separate PEM files. Keys can also be specified for specific purposes (e.g. public key for encryption and private key for decryption).
* Example usage
  * Generation
    * python asym_enc.py -m generate
    * python asym_enc.py -m generate -s 4096
  * Encryption
    * python asym_enc.py -m encrypt -k rsa_public.pem -t test.txt
  * Decryption
    * python asym_enc.py -m decrypt -k rsa_private.pem -t test.txt
* Other notes
  * If a target directory is specified instead of a file, the program will recursively encrypt or decrypt all files within the directory
  * The contents of files will be encrypted, but the file extensions will remain unmodified
