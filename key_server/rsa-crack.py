#!/usr/bin/env python

import glob

from fractions import gcd

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception("mod inverse does not exist")
    else:
        return x % m


def get_public_keys():
    """ Returns a list of RSA public keys from the public folder """

    public_keys = glob.glob('public/*.pem')

    result = {}
    for public_key in public_keys:
        with open(public_key) as f:
            name = public_key.replace('public/', '')
            name = name.replace('.pem', '')
            data = f.read()
            key = RSA.importKey(data)
            result[name] = key.__getattr__('n')
    return result


def get_greatest_common_divisor(key1, key2):
    return gcd(rsa_pkeys[name1], rsa_pkeys[name2])


def reconstruct_private_key(n, p, q):
    e = 65537  # commonly used value
    d = modinv(e, n - (p + q - 1))

    key = RSA.construct((n, long(e), d, p, q))
    # print key.exportKey()

    return key


def sign_message(key, text):
    h = SHA.new(text)
    signer = PKCS1_v1_5.new(key)

    return signer.sign(h)


def verify_message(username, text, signature):
    key = RSA.construct((rsa_pkeys[username], long(65537)))
    # print key.exportKey()
    h = SHA.new(text)
    signer = PKCS1_v1_5.new(key)

    return signer.verify(h, signature)


if __name__ == "__main__":
    rsa_pkeys = get_public_keys()

    for name1 in rsa_pkeys:
        for name2 in rsa_pkeys:
            if name1 != name2:
                cd = get_greatest_common_divisor(
                    rsa_pkeys[name1], rsa_pkeys[name2])
                if cd != 1:
                    print "[+] {} Has a weak public key".format(name1)
                    print "{} and {} share the same common divisor of {}".format(name1, name2, cd)
                    n = rsa_pkeys[name1]
                    p = cd
                    q = n / p

                    # print cd
                    # print q

                    key = reconstruct_private_key(n, p, q)

                    signed_message = sign_message(key, 'admin')

                    print "Signed message as {}: {}".format(name1, signed_message.encode('hex'))
                    valid_private_key = verify_message(
                        name1, 'admin', signed_message)

                    if valid_private_key:
                        print "Verifies using public key. Writing to disk.\n\n"
                        file = open('private/{}.pem'.format(name1), 'w')
                        file.write(key.exportKey())
                        file.close()
