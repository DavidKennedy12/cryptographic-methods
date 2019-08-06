import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss

# Instead of storing files on disk,
# we'll save them in memory for simplicity
filestore = {}
# Valuable data to be sent to the botmaster
valuables = []

def save_valuable(data):
    valuables.append(data)

def encrypt_for_master(data):
    # Import public key
    pub = RSA.import_key(open("public_key.pem").read())
    # Generate session key
    key = get_random_bytes(16)
    # Enrypt data using session key
    data_enc = AES.new(key = key, mode = AES.MODE_CTR, nonce = bytes(0)).encrypt(data)
    # Encrypt session key using public key
    key_enc = PKCS1_OAEP.new(pub).encrypt(key)
    # Append encrypted session key to encrypted data
    return key_enc + data_enc

def upload_valuables_to_pastebot(fn):
    # Encrypt the valuables so only the bot master can read them
    valuable_data = "\n".join(valuables)
    valuable_data = bytes(valuable_data, "ascii")
    encrypted_master = encrypt_for_master(valuable_data)

    # "Upload" it to pastebot (i.e. save in pastebot folder)
    f = open(os.path.join("pastebot.net", fn), "wb")
    f.write(encrypted_master)
    f.close()
    print("Saved valuables to pastebot.net/%s for the botnet master" % fn)

def verify_file(f):
    # Import public key
    pub = RSA.import_key(open('public_key.pem').read())
    # Create verifier with public key
    verifier = pss.new(pub)
    # Extract signature, RSA-3072 ==> 384 bytes
    signature = f[0:384]
    # Extract file
    data = f[384:]
    # Hash file
    h = SHA256.new(data) 
    # Verify signature of hashed file
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
    
def process_file(fn, f):
    if verify_file(f):
        # If it was, store it unmodified
        # (so it can be sent to other bots)
        # Decrypt and run the file
        filestore[fn] = f
        print("Stored the received file as %s" % fn)
    else:
        print("The file has not been signed by the botnet master")

def download_from_pastebot(fn):
    # "Download" the file from pastebot.net
    # (i.e. pretend we are and grab it from disk)
    # Open the file as bytes and load into memory
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        return
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    process_file(fn, f)

def p2p_download_file(sconn):
    # Download the file from the other bot
    fn = str(sconn.recv(), "ascii")
    f = sconn.recv()
    print("Receiving %s via P2P" % fn)
    process_file(fn, f)

def p2p_upload_file(sconn, fn):
    # Grab the file and upload it to the other bot
    # You don't need to encrypt it only files signed
    # by the botnet master should be accepted
    # (and your bot shouldn't be able to sign like that!)
    if fn not in filestore:
        print("That file doesn't exist in the botnet's filestore")
        return
    print("Sending %s via P2P" % fn)
    sconn.send(bytes(fn, 'ascii'))
    sconn.send(bytes(filestore[fn]))

def run_file(f):
    # If the file can be run,
    # run the commands
    pass
