''' 
    TinyPass crypto library for encrypting/decrypting/signing data passed via APIs and webhooks.
    Notes:
    - TinyPass uses your full private key for computing checksums, but...
    - TinyPass uses only the first 32 chars of your private for encrypting the data

    The b64encrypt and b64decrypt can be used but they expose their data as simply b64 encoded,
    so anyone can decoded and thus debug the mechanics of the system, but you should switch over
    to the aesencrypt/aesdecrypt calls as soon as practical, and always for production systems.

'''

import base64
import hashlib
import hmac
import json


TINYPASS_DELIM = '~~~'


def compute_checksum(key, value):
    dig = hmac.new(key, msg=value, digestmod=hashlib.sha256).digest()
    urlsafe_computed_checksum = base64.b64encode(
        dig, altchars="-_").rstrip("=")

    return urlsafe_computed_checksum


def b64encrypt(key, value):
    # encrypt it
    encoded = base64.b64encode(value, altchars="-_").rstrip("=")

    # sign it
    checksum = compute_checksum(key, encoded)

    # pack it up
    ciphertext = encoded + TINYPASS_DELIM + checksum

    return ciphertext


def b64decrypt(key, data):
    # unpack it
    encoded, checksum = data.split(TINYPASS_DELIM)

    # decrypt it
    # add padding.   pythong ignores it if it is extra
    decoded = base64.b64decode(encoded + "==", altchars="-_")

    # do we trust it?
    computed_checksum = compute_checksum(key, encoded)
    if checksum != computed_checksum:
        print "checksum != computed", checksum, computed_checksum
        raise ValueError("oops, checksum failed on {data}. Shenanigans sending {decoded}!".format(
            data=data, decoded=decoded))

    return decoded


def test_tinypass_b64encrypt_decrypt():
    plain = "test"
    ciphertext = b64encrypt('secret', plain)
    #'dGV4dA~~~B2e7u4TkmicXP_lLwvaxFyHbzPZUXxJ4FhorPg0jm_c'
    output = b64decrypt('secret', ciphertext)
    assert plain == output, 'tinypass encrypt -> decrypt cycle failed. {} became {}'.format(
        plain, output)


###
# rjindael encryption routines
# it turns out rjindael is aes forced to 16 byte blocks
###
import pprp
import io


def blockgen(bytes, block_size=16):
    ''' a block generator for pprp '''
    for i in range(0, len(bytes), block_size):
        block = bytes[i:i + block_size]
        block_len = len(block)
        if block_len > 0:
            yield block
        if block_len < block_size:
            break

def expand_key( passphrase, salt="tinypass", key_size=32 ):
    # this is the propper way to expand a key, but the tinypass example code pads with X's
    ekey = pprp.pbkdf2(passphrase, salt, key_size)
    ekey = (passphrase + "X"*key_size)[:key_size]
    return ekey


def aesdecrypt(key, data):
    ekey = expand_key( key )
    cut_key = ekey[:32]

    # unpack
    cipher_text, checksum = data.split(TINYPASS_DELIM)

    # decode
    cipher_bytes = base64.b64decode(cipher_text + "==", altchars="-_")

    # decrypt
    blocks = blockgen(cipher_bytes, block_size=16)
    decryptor = pprp.rjindael_decrypt_gen(cut_key, blocks, block_size=16)

    # accumulate the blocks
    acc = io.BytesIO()
    for block in decryptor:
        acc.write(block)

    # coalesce
    val = acc.getvalue()

    # funny story: because it encrypts data in blocks, the last block might
    # have some extra data at the end.  The good news is that the last byte
    # will indicate how many bytes of garbage are on the end.  Luckily our 
    # data should never end in characters 1-16.
    padding = ord(val[-1])
    if padding >= 0 and padding <= 16:
        val = val[:-padding]

    # check it, do we trust it?
    # we could do this first to avoid the work of decryption, but I want to
    # log the decrypted value, so we wait to have that value.
    computed_checksum = compute_checksum(key, cipher_text)
    #'r5lqwhbZsooVQFO-ZZbnT7AB36hE2Dz-OebhcLBlVs8='
    if computed_checksum != checksum:
        print "checksum != computed", checksum, computed_checksum
        raise ValueError("oops, checksum failed on {data}. Shenanigans sending {decoded}!".format(
            data=data, decoded=val))

    return val


def aesencrypt(key, val):
    # encrypt
    ekey = expand_key(key)
    cut_key = ekey[:32]

    blocks = blockgen(val, block_size=16)

    encryptor = pprp.rjindael_encrypt_gen(cut_key, blocks, block_size=16)

    s = io.BytesIO()
    for block in encryptor:
        s.write(block)

    cipher_bytes = s.getvalue()

    # encode
    cipher_text = base64.b64encode(cipher_bytes, altchars="-_").rstrip("=")

    # pack it up
    checksum = compute_checksum(key, cipher_text)
    data = cipher_text + TINYPASS_DELIM + checksum

    return data

