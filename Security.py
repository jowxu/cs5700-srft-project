import os
import struct
from  cryptography.hazmat.primitives.ciphers.aead import AESGCM

NonceSize = 12

def build_aad(session_id, seq_num, ack_num, p_type):
    return struct.pack('!8sIIB', session_id, seq_num, ack_num, p_type)

def build_nonce(seq_num):
    return seq_num.to_bytes(NonceSize, byteorder='big')

def encrypt_payload(enc_key, session_id, seq_num, ack_num, p_type, plaintext):
    aad   = build_aad(session_id, seq_num, ack_num, p_type)
    nonce = build_nonce(seq_num)
 
    # AESGCM takes the key and handles encrypt/decrypt
    # encrypt() returns ciphertext with the 16-byte tag already appended
    aesgcm = AESGCM(enc_key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
 
    # prepend nonce so the receiver can reconstruct it for decryption
    return nonce + ciphertext_with_tag

def decrypt_payload(enc_key, session_id, seq_num, ack_num, p_type, encrypted_payload):
    # extract nonce from the first NONCE_SIZE bytes
    nonce = encrypted_payload[:NonceSize]
    ciphertext_with_tag = encrypted_payload[NonceSize:]
 
    aad = build_aad(session_id, seq_num, ack_num, p_type)
 
    aesgcm = AESGCM(enc_key)
 
    # decrypt() raises InvalidTag automatically if authentication fails
    # no need to check manually — just let the exception propagate to the caller
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
 
    return plaintext
 
