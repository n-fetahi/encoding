import http
from django.shortcuts import render,HttpResponse
import random
import math
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from os.path import splitext
from tkinter import *
from tkinter import filedialog, messagebox

# Create your views here.

def home(request):
    return render(request,'encrypt.html')


# Generate RSA key pair for Alice and Bob
alice_key = RSA.generate(2048)
bob_key = RSA.generate(2048)

# Generate Diffie-Hellman key pair for Bob
def generate_dh_key_pair():
    # Choose a large prime number p and a generator g
    p = random.randint(100, 1000)
    g = random.randint(2, p-1)

    # Choose a secret key a
    a = random.randint(2, p-2)

    # Compute the public key A
    A = pow(g, a, p)

    return (p, g, a, A)

bob_dh_key_pair = generate_dh_key_pair()

# Compute shared secret key K using Bob's DH public key and Alice's RSA private key
def compute_shared_secret_key(bob_public_key, alice_private_key):
    p, g, a, A = bob_dh_key_pair[0], bob_dh_key_pair[1], int(alice_key.n), alice_dh_key_pair[3]
    B = pow(g, a, p)
    s = pow(bob_public_key, a, p)
    K = str(s).zfill(16) # Pad the shared secret key with zeros to make sure it has length 16
    return K

# Generate Diffie-Hellman key pair for Alice and compute shared secret key K
alice_dh_key_pair = generate_dh_key_pair()
K = compute_shared_secret_key(bob_dh_key_pair[3], alice_key)

# Encrypt message using shared secret key K and AES-GCM algorithm
def encrypt_message(message, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    nonce = cipher.nonce
    return ciphertext, nonce, tag

# Encrypt shared secret key K using Bob's RSA public key
rsa_cipher = PKCS1_OAEP.new(RSA.import_key(bob_key.publickey().export_key()))
encrypted_key = rsa_cipher.encrypt(K.encode('utf-8'))

# Decrypt encrypted shared secret key using Bob's RSA private key and compute shared secret key K
rsa_cipher = PKCS1_OAEP.new(bob_key)
try:
    decrypted_key = rsa_cipher.decrypt(encrypted_key)
    K = compute_shared_secret_key(int.from_bytes(decrypted_key, byteorder='big'), bob_dh_key_pair[2])
except ValueError:
    messagebox.showerror("Error", "Failed to decrypt the shared secret key.")

# Decrypt message using shared secret key K and AES-GCM algorithm
def decrypt_message(ciphertext, key, nonce, tag):

    cipher = AES.new(key.encode('utf-8'), AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except ValueError:
        return HttpResponse('Failed to decrypt the message.')
# GUI functions
nonce = 0
tag = 0

def encrypt(request):
    message = str(request.POST['message']).strip()
    if message == "":
        messagebox.showerror("Error", "Please enter a message to encrypt.")
        return

    # Encrypt the message
    ciphertext, nonce, tag = encrypt_message(message.encode('utf-8'), K)
    # return HttpResponse(ciphertext)
    return render(request,'encrypt.html',{
                'message':request.POST['message'],

        'ciphertext':ciphertext.hex(),
        'nonce':nonce.hex(),
        'tag':tag.hex(),
    })


def decrypt(request):
    ciphertext_hex = str(request.POST['encrypted']).strip()
    # return HttpResponse(request.POST)

    if ciphertext_hex == "":
        return HttpResponse('Please enter an encrypted message to decrypt.')

    # Get the nonce and tag from the GUI

    nonce = bytes.fromhex(str(request.POST['nonce']))

    tag = bytes.fromhex(str(request.POST['tag']))

    # Decrypt the message
    ciphertext = bytes.fromhex(ciphertext_hex)
    try:
        decrypted_message = decrypt_message(ciphertext, K, nonce, tag)
    except ValueError as e:
        # messagebox.showerror("Error", str(e))
        return

    # Display the decrypted message
    return render(request,'encrypt.html',{
        'message':request.POST['message'],
        'ciphertext':ciphertext.hex(),
        'nonce':nonce.hex(),
        'tag':tag.hex(),
        'decrypt_text':   decrypted_message.decode('utf-8')
    })
    decrypted_message_entry.delete('1.0', END)
    decrypted_message_entry.insert('1.0', decrypted_message.decode('utf-8'))


# Create GUI
# root = Tk()

# # Message Encryption GUI
# message_frame = LabelFrame(root,text="Message Encryption")
# message_frame.pack(fill="both", expand="yes", padx=20, pady=10)

# # Message entry
# message_label = Label(message_frame, text="Message:")
# message_label.grid(row=0, column=0, padx=10, pady=10)
# message_entry = Text(message_frame, width=50, height=5)
# message_entry.grid(row=0, column=1, padx=10, pady=10)

# # Encrypt button
# encrypt_button = Button(message_frame, text="Encrypt", command=encrypt_message_gui)
# encrypt_button.grid(row=1, column=0, columnspan=2, pady=10)


# # Message Decryption GUI
# decryption_frame = LabelFrame(root, text="Message Decryption")
# decryption_frame.pack(fill="both", expand="yes", padx=20, pady=10)

# # Encrypted message entry
# encrypted_message_label = Label(decryption_frame, text="Encrypted Message:")
# encrypted_message_label.grid(row=0, column=0, padx=10, pady=10)
# encrypted_message_entry = Text(decryption_frame, width=50, height=5)
# encrypted_message_entry.grid(row=0, column=1, padx=10, pady=10)

# # Nonce entry
# nonce_label = Label(decryption_frame, text="Nonce:")
# nonce_label.grid(row=1, column=0, padx=10, pady=10)
# nonce_entry = Entry(decryption_frame, width=50)
# nonce_entry.grid(row=1, column=1, padx=10, pady=10)

# # Tag entry
# tag_label = Label(decryption_frame, text="Tag:")
# tag_label.grid(row=2, column=0, padx=10, pady=10)
# tag_entry = Entry(decryption_frame, width=50)
# tag_entry.grid(row=2, column=1, padx=10, pady=10)

# # Decrypt button
# decrypt_button = Button(decryption_frame, text="Decrypt", command=decrypt_message_gui)
# decrypt_button.grid(row=3, column=0, columnspan=2, pady=10)

# # Decrypted message entry
# decrypted_message_label = Label(decryption_frame, text="Decrypted Message:")
# decrypted_message_label.grid(row=4, column=0, padx=10, pady=10)
# decrypted_message_entry = Text(decryption_frame, width=50, height=5)
# decrypted_message_entry.grid(row=4, column=1, padx=10, pady=10)

# Run GUI
# root.mainloop()

