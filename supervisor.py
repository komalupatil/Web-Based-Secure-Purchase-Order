import socket
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
from Crypto import Random
from base64 import b64encode, b64decode
import sqlite3, hashlib, os
hash = "SHA-256"
def newkeys(keysize):
    random_generator = Random.new().read
    key = RSA.generate(keysize, random_generator)
    private, public = key, key.publickey()
    return public, private

def importKey(externKey):
    return RSA.importKey(externKey)

def getpublickey(priv_key):
    return priv_key.publickey()
def encrypt(message, pub_key):
    #RSA encryption protocol according to PKCS#1 OAEP
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(message)

def decrypt(ciphertext, priv_key):
    #RSA encryption protocol according to PKCS#1 OAEP
    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(ciphertext)

def sign(message, priv_key, hashAlg="SHA-256"):
    global hash
    hash = hashAlg
    signer = PKCS1_v1_5.new(priv_key)
    if (hash == "SHA-512"):
        digest = SHA512.new()
    elif (hash == "SHA-384"):
        digest = SHA384.new()
    elif (hash == "SHA-256"):
        digest = SHA256.new()
    elif (hash == "SHA-1"):
        digest = SHA.new()
    else:
        digest = MD5.new()
    digest.update(message)
    return signer.sign(digest)

def verify2(message, signature, pub_key):
    signer = PKCS1_v1_5.new(pub_key)
	
    if (hash == "SHA-512"):
        digest = SHA512.new()
    elif (hash == "SHA-384"):
        digest = SHA384.new()
    elif (hash == "SHA-256"):
        digest = SHA256.new()
    elif (hash == "SHA-1"):
        digest = SHA.new()
    else:
        digest = MD5.new()
    digest.update(message)
    return signer.verify(digest, signature)
msg = b'I am the supervisor'
keysize = 1024
(public, private) = newkeys(keysize)

publickeyD='-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHt/J2Z9QCo7jjgxUA4GdDffol\nJExrfgDJHzaKVWKga4fnQl4lh7Rve2dBNkq7QSrjFOjG0J+h1YMpcrFyQGtPmaVb\nUeTepTvUcqqY7M+O+3kkCkxAnf7sM5XrbjFQb7YyFw0hqa8QsNj+UVK2ffKbJ2Pi\nX9x8ubt8JY4DNTa2HQIDAQAB\n-----END PUBLIC KEY-----'
publickeysup='-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHt/J2Z9QCo7jjgxUA4GdDffol\nJExrfgDJHzaKVWKga4fnQl4lh7Rve2dBNkq7QSrjFOjG0J+h1YMpcrFyQGtPmaVb\nUeTepTvUcqqY7M+O+3kkCkxAnf7sM5XrbjFQb7YyFw0hqa8QsNj+UVK2ffKbJ2Pi\nX9x8ubt8JY4DNTa2HQIDAQAB\n-----END PUBLIC KEY-----'
privatekeySup='-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQDHt/J2Z9QCo7jjgxUA4GdDffolJExrfgDJHzaKVWKga4fnQl4l\nh7Rve2dBNkq7QSrjFOjG0J+h1YMpcrFyQGtPmaVbUeTepTvUcqqY7M+O+3kkCkxA\nnf7sM5XrbjFQb7YyFw0hqa8QsNj+UVK2ffKbJ2PiX9x8ubt8JY4DNTa2HQIDAQAB\nAoGACju0oriDNndpG881nkvhPqYP0SNg/wj/xU5iHwhs+0dHOWQ/KrEfX671BXRg\ns+OM7QG/Q6Cg7UvhYphL20zNsrk+lMZj//ZRSrlLIbgMHr515qH5gyanDaUQ9NuH\nOwDZLsUOXVwml3Bg/9NLPCesFQvas5yuHiBegNo4mVTN+0kCQQDZ2TEvfQyM15cj\njSVwTEGTCofhLDPXczcBQszENTXL+ECMkV92oWHQmF4OiiRGJ43S3hvy3St8HziW\nXRAHkWkXAkEA6rHwHv36eeC6v6ZyLT1o9gd0rhHIwrfm5Ku2LxX71ZYGaU+ClFWH\nT9QM82rX1A7/6uD+bhXSWNrWLpDjhOly6wJAObcsK8uyjoHzveyANb9ORDmvBD4k\nwfj5YrEi9Pyv8wkjeNpu80wQUSZ9DNcWgyupjGth9jcYdTsET/n57DdfIwJAFVQ+\nglKKpPDrh+dUkQ/3rgRXckpjeG7GKRoB4J2a2Xpc8s0rDNgJCBQ5aRXYr4j9cRcp\niE+rYi/hLzIzuyyMKQJBAJIzR/zBm6m+FxvE5QIwM1XDDAXcQAVxHI+W9ev70sq/\nYdYrg6KZ/CFkN0BaF2apqHoSTIgaCiOWeofIsY7+SSc=\n-----END RSA PRIVATE KEY-----'
privateSupSign='-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQDBTWVhm7y2G1QI+LY1V7TVN7VQglUq3BnDUrk3ChCQCNLvuRJE\nJ4pOuMtQ5iXdcb4zm71IWxR/jv+KC4iJTuWjAuBQWBlpeV00HlqHcOVvYBwccuhm\ntjiBrqb5VV6mvesLoW/WodPDP8wIrTya2a552umL8tv5HwG2xUenK3kmHwIDAQAB\nAoGAXvDBDQ5dQwIsJZXmhE+WES0h4C+LXhgpjS4pqxdF6EB1Pemjx5a2DxEjRxIq\n4dc2SInDD3EwobAd4XLlti7qiOnEq7Lhs6x9BtcQhZ5B6eBIu1Y9KkH4ZqNguwy2\nJ4aWuNN4ck+/KHz6Rq4ZNYTdXN5KWdZNr86woeyiHKPdpxkCQQDXcVgIKw8atxJy\na0CGET9EQ2cSoeK2eBv1DS2PORJX0YteSNnoTvDX2HlZ8DU+EMWJbSPIEJIa40u6\nTCzYay6nAkEA5bEOk6AGpTg6cejaeEqS0FKR13UW3F/qtRmu6JQOFYY2nFIjhcip\nEIMqKIf/M9ghXeETrftIkYSz5EMbD8/zyQJBAK0ZNFHbxtcAIKIt6jnNwbdnMHmX\n+EADYPMTE3fvsv08L24hunMcegXyuA27IgwsDYrNVeJ47esMlNuqOJ3qACECQGV2\nfy/rIsRdQEQNTmSQ3KW1s8LvcDfNDwsM21zV+hq7/Oe0yQhSCYzHxBm/aZZnROYJ\nhP334KiXbDfLBOtJOzECQFLn4KC/irt7pThqMv+vcUIQjRvs6A/clOJd6Hy/0RX3\npC4FjdftyUKGwAyNzf0njsyNH5kfQz5mizKkBceDqII=\n-----END RSA PRIVATE KEY-----'
publicD = importKey(publickeyD)
publicS = importKey(publickeysup)
privateS= importKey(privatekeySup)
privateSupS= importKey(privateSupSign)
encrypted = b64encode(encrypt(msg, publicD))

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = ('localhost', 10000)
print (sys.stderr, 'connecting to %s port %s' % server_address)
sock.connect(server_address)
try:
    
    # Send data
    sock.send(encrypted)

    # Look for the response
    amount_received = 0
    amount_expected = 1024
    #while(amount_received < amount_expected):
    data = sock.recv(1024)               
    print (sys.stderr, 'received "%s"' % data)
    
    
    dataD = decrypt(b64decode(data), privateS)
    print(dataD)
    message = ' '
    listmsg = []
    
    orderid = input("Which order do you want to approve? ")
    sock.send(orderid.encode())
    answer= input("Do you want to sign it? ")
    if (answer=='yes' or answer=='Yes'):
          with sqlite3.connect('database.db') as conn:
              cur = conn.cursor()
              cur.execute("SELECT userId FROM orders WHERE orderid = " + str(orderid))
              userId = cur.fetchone()[0]
              cur.execute("SELECT timestamp FROM  orders WHERE orderid = " + str(orderid) )
              timestamp = cur.fetchone()[0]
              message = str(userId)+str(orderid)+str(timestamp)
              message = message.encode()
          conn.close()
          signaturesup = b64encode(sign(message, privateSupS, "SHA-256"))
          sock.send(signaturesup)
    else:
        print("exiting application")
        sock.close()
    done=input("Are you done?")
    sock.send(done.encode())  

    
finally:
    if (done=='done' or done=='Done'):
        print ('closing socket')
        sock.close()

