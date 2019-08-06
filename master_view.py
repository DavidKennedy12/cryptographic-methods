import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP

def decrypt_valuables(f):
    # Import private key
    priv = RSA.import_key(open('private_key.pem').read())
    # Extract encrypted session key, RSA-3072 ==> 384 bytes
    key_enc = f[0:384]
    # Extract encrypted data
    data_enc = f[384:]
    # Decrypt session key using private key
    key = PKCS1_OAEP.new(priv).decrypt(key_enc)
    # Decrypt data using session key
    data = AES.new(key = key, mode = AES.MODE_CTR, nonce = bytes(0)).decrypt(data_enc)    
    
    decoded_text = str(data, 'ascii')
    print(decoded_text)

if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)