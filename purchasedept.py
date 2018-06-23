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
    global data
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
msg = b'I am from purchase department'
keysize = 1024
(public, private) = newkeys(keysize)
privatekey='-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQDHt/J2Z9QCo7jjgxUA4GdDffolJExrfgDJHzaKVWKga4fnQl4l\nh7Rve2dBNkq7QSrjFOjG0J+h1YMpcrFyQGtPmaVbUeTepTvUcqqY7M+O+3kkCkxA\nnf7sM5XrbjFQb7YyFw0hqa8QsNj+UVK2ffKbJ2PiX9x8ubt8JY4DNTa2HQIDAQAB\nAoGACju0oriDNndpG881nkvhPqYP0SNg/wj/xU5iHwhs+0dHOWQ/KrEfX671BXRg\ns+OM7QG/Q6Cg7UvhYphL20zNsrk+lMZj//ZRSrlLIbgMHr515qH5gyanDaUQ9NuH\nOwDZLsUOXVwml3Bg/9NLPCesFQvas5yuHiBegNo4mVTN+0kCQQDZ2TEvfQyM15cj\njSVwTEGTCofhLDPXczcBQszENTXL+ECMkV92oWHQmF4OiiRGJ43S3hvy3St8HziW\nXRAHkWkXAkEA6rHwHv36eeC6v6ZyLT1o9gd0rhHIwrfm5Ku2LxX71ZYGaU+ClFWH\nT9QM82rX1A7/6uD+bhXSWNrWLpDjhOly6wJAObcsK8uyjoHzveyANb9ORDmvBD4k\nwfj5YrEi9Pyv8wkjeNpu80wQUSZ9DNcWgyupjGth9jcYdTsET/n57DdfIwJAFVQ+\nglKKpPDrh+dUkQ/3rgRXckpjeG7GKRoB4J2a2Xpc8s0rDNgJCBQ5aRXYr4j9cRcp\niE+rYi/hLzIzuyyMKQJBAJIzR/zBm6m+FxvE5QIwM1XDDAXcQAVxHI+W9ev70sq/\nYdYrg6KZ/CFkN0BaF2apqHoSTIgaCiOWeofIsY7+SSc=\n-----END RSA PRIVATE KEY-----'
publickey='-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHt/J2Z9QCo7jjgxUA4GdDffol\nJExrfgDJHzaKVWKga4fnQl4lh7Rve2dBNkq7QSrjFOjG0J+h1YMpcrFyQGtPmaVb\nUeTepTvUcqqY7M+O+3kkCkxAnf7sM5XrbjFQb7YyFw0hqa8QsNj+UVK2ffKbJ2Pi\nX9x8ubt8JY4DNTa2HQIDAQAB\n-----END PUBLIC KEY-----'
publickeySup='-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHt/J2Z9QCo7jjgxUA4GdDffol\nJExrfgDJHzaKVWKga4fnQl4lh7Rve2dBNkq7QSrjFOjG0J+h1YMpcrFyQGtPmaVb\nUeTepTvUcqqY7M+O+3kkCkxAnf7sM5XrbjFQb7YyFw0hqa8QsNj+UVK2ffKbJ2Pi\nX9x8ubt8JY4DNTa2HQIDAQAB\n-----END PUBLIC KEY-----'
publicsignsup='-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBTWVhm7y2G1QI+LY1V7TVN7VQ\nglUq3BnDUrk3ChCQCNLvuRJEJ4pOuMtQ5iXdcb4zm71IWxR/jv+KC4iJTuWjAuBQ\nWBlpeV00HlqHcOVvYBwccuhmtjiBrqb5VV6mvesLoW/WodPDP8wIrTya2a552umL\n8tv5HwG2xUenK3kmHwIDAQAB\n-----END PUBLIC KEY-----'
publicusersign='-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6OHWNGCAizb/DGi3JDbD54go0\nHaWTnyaR5Le7k2EE4Gqm3oCXH9fD0WQoOoXvGEeki0FbKkqAcPjZ0kFxY3xtPWio\nfhokwismJG3ZO1NHAGVtetM1VRQ+usRmuVtQZi91KBAL7buf50oJl8gQDtRtDT6W\nVH1Lk0AaP0bFEEsxVQIDAQAB\n-----END PUBLIC KEY-----'
PUuserSign=importKey(publicusersign)
privateD = importKey(privatekey)
publicD = importKey(publickey)
publicS= importKey(publickeySup)
publicsignS=importKey(publicsignsup)
encrypted = b64encode(encrypt(msg, publicS))
# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Bind the socket to the port
server_address = ('localhost', 10000)
print (sys.stderr, 'starting up on %s port %s' % server_address)
sock.bind(server_address)
# Listen for incoming connections
sock.listen(1)
    # Wait for a connection
print (sys.stderr, 'waiting for a connection')
connection, client_address = sock.accept()
connection.send(encrypted)
try:
    print (sys.stderr, 'connection from', client_address)
    # Receive the data in small chunks and retransmit it   
    data = connection.recv(1024)       
    if data:
        print (sys.stderr, 'received "%s"' % data)
    dataD = decrypt(b64decode(data), privateD)
    print(dataD)
    message=' '
    listmsg = []
    
    #message = input(" -> ")
    
    while (message != 'done' or message != 'Done'):
        try:
            data1 = connection.recv(1024).decode()
        except:
            break
        if(data1 == 'done'):
            connection.close()
        else:
            listmsg.append(data1)
            print ('Received from client: ' + str(data1))
            message = input(" -> ")
            if(message=='done'):
                break
            try:
                connection.send(message.encode())
            except:
                pass
        
        
    orderid=listmsg[0]
    supsign=str(listmsg[1])
    supsign=supsign.encode()
    print(supsign)
    
    with sqlite3.connect('database.db') as conn:
        cur = conn.cursor()
        cur.execute("SELECT userId FROM orders WHERE orderid = " + str(orderid))
        userId = cur.fetchone()[0]
        cur.execute("SELECT timestamp FROM  orders WHERE orderid = " + str(orderid) )
        timestamp = cur.fetchone()[0]
        print("a")
        message = str(userId)+str(orderid)+str(timestamp)
        message = message.encode()
    conn.close()
    print("c")
    verify = verify2(message, b64decode(supsign), publicsignS)
    print("Verify: %s" % verify)
    if(verify==True):
        print("Supervisor sign verified")
    else:
        print("Supervisor sign not verified")
    userSign = input("Enter User's signature: ")
    userSign= userSign.encode()
    verify1 = verify2(message, b64decode(userSign), PUuserSign)
    if(verify1==True):
        print("User sign verified")
    else:
        print("User sign not verified")
    if(verify==True and verify1==True):
        with sqlite3.connect('database.db') as conn:
            try:
                cur = conn.cursor()
                cur.execute("update orders set flag='True' where orderid="+str(orderid))
                conn.commit()
            except:
                conn.rollback()
        conn.close()
    
            
finally:
    print("Orders is approved and is sent to delivery team")
    # Clean up the connection
    connection.close()
