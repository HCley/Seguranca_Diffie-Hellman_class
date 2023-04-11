import argparse
import hashlib
import yaml

from Crypto.Util import number
from base64 import b64encode, b64decode
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES
from yaml.loader import SafeLoader

encoding = 'utf-8'
fileConfName = 'conf.yaml'

parser = argparse.ArgumentParser()
parser.add_argument('--generate_prime', type=int,
                    help='Generate prime number with <param> bit length')
parser.add_argument('--public_key', required=False, action='store_true',
                    help='Generate primary key (needs [sk, p, g])')
parser.add_argument('--exchange', required=False,
                    action='store_true', help='Exchange keys (needs [pk, sk, p])')
parser.add_argument('--encrypt', required=False,
                    action='store_true', help='Encrypt message with private key (needs [pk, message])')
parser.add_argument('--decrypt', required=False,
                    action='store_true', help='Decrypt \'message with private key (needs [pk, \'message])')
parser.add_argument('-pk', dest='pk', help='Primary key to exchange method')
parser.add_argument('-sk', dest='sk', help='Secret key to exchange method')
parser.add_argument('-m', dest='m', help='message')
parser.add_argument('-p', dest='p', help='p module')
parser.add_argument('-g', dest='g', help='g base')
args = parser.parse_args()


def encrypt(plain_text, password):
    # generate a random salt
    salt = get_random_bytes(AES.block_size)

    # use the Scrypt KDF to get a private key from the password
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # create cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)

    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(
        bytes(plain_text, 'utf-8'))
    return {
        'cipher_text': b64encode(cipher_text).decode('utf-8'),
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }


def decrypt(m, password):

    with open(fileConfName) as f:
        data = yaml.load(f, Loader=SafeLoader)
    # decode the dictionary entries from base64

    salt = b64decode(data['salt'])
    cipher_text = b64decode(m)
    nonce = b64decode(data['nonce'])
    tag = b64decode(data['tag'])

    # generate the private key from the password and salt
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # create the cipher config
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

    # decrypt the cipher text
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)

    return decrypted


bitLength = args.generate_prime
publicKey = args.public_key
exchange = args.exchange
encryptopt = args.encrypt
decryptopt = args.decrypt

secretKey = args.sk
pk = args.pk
g = args.g
p = args.p
m = args.m

if bitLength:
    print(str(bitLength) + ' bits prime number: \n' +
          str(number.getPrime(int(bitLength))))

elif publicKey == True or exchange == True:
    if not g:
        g = pk
    print(pow(int(g), int(secretKey), int(p)))

elif encryptopt:
    e = encrypt(m, pk)
    print(e['cipher_text'])
    del e['cipher_text']
    with open(fileConfName, 'w') as f:
        data = yaml.dump(e, f, sort_keys=False, default_flow_style=False)


elif decryptopt:
    print(decrypt(m, pk).decode(encoding))
