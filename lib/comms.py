import struct
from dh import create_dh_key, calculate_dh_secret
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.client = client
        self.server = server
        self.verbose = verbose
        self.key = None
        # Counter used to ensure uniqueness of nonce and prevent replay
        self.counter = 0
        # Store seen counters to prevent replay
        self.seen = set()
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret 
        # This can be broken into code run just on the server or just on the clientasdsad
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            # Take first 16 bytes of the (32 byte) hash as the key
            self.key = shared_hash[:16] 
            print("Shared hash: {}".format(shared_hash.hex()))


    def send(self, data):
        if self.key:
            self.counter += 1
            nonce = get_random_bytes(8)
            # The nonce is 8 random bytes concatenated with the 4 byte counter
            nonce += self.counter.to_bytes(4, byteorder = 'big')
            cipher = AES.new(self.key, AES.MODE_GCM, nonce)
            # Encrypt the plain text and generate an authentication tag
            cipher_text, tag = cipher.encrypt_and_digest(data)
            # MAC||IV||Cipher Text
            encrypted_data = tag + nonce + cipher_text
            print("encrypted_data--->", encrypted_data)
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]
        encrypted_data = self.conn.recv(pkt_len)
        
        if self.key:
            # First 16 bytes is the MAC
            tag = encrypted_data[:16] 
            # Next 12 bytes is the Nonce
            nonce = encrypted_data[16:28]
            # Last 4 bytes of the nonce is the counter
            count = int.from_bytes(nonce[8:], byteorder='big') 
            # After 28 bytes is the cipher text
            cipher_text = encrypted_data[28:] 
            if count in self.seen:
                print("Error: Repeated Counter Number", count)
                # Don't decrpyt the data, replay attack
                data = encrypted_data
            else:
                self.seen.add(count)
                self.cipher = AES.new(self.key, AES.MODE_GCM, nonce)
                # Decrypt the data and verify it using the provided tag
                data = self.cipher.decrypt_and_verify(cipher_text, tag)
                print("decrypted_data--->", )
                if self.verbose:
                    print("Receiving packet of length {}".format(pkt_len))
                    print("Encrypted data: {}".format(repr(encrypted_data)))
                    print("Original data: {}".format(data))
        else:
            data = encrypted_data

        return data

    def close(self):
        self.conn.close()
