from tkinter import messagebox
from tkinter import *
from tkinter import simpledialog
import tkinter
from tkinter import filedialog
from tkinter.filedialog import askopenfilename
from tkinter import ttk
import os
import numpy as np
from PIL import Image
import base64
from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt
import hashlib
import os
import zlib

main = Tk()
main.title("Securing data in the image using SHA & ECC")
main.geometry("1300x1200")

global filename, sender_sha

#function to generate public and private keys for ECC algorithm
def ECCGenerateKeys():
    if os.path.exists("pvt.key"):
        with open("pvt.key", 'rb') as f:
            private_key = f.read()
        f.close()
        with open("pri.key", 'rb') as f:
            public_key = f.read()
        f.close()
        private_key = private_key.decode()
        public_key = public_key.decode()
    else:
        secret_key = generate_eth_key()
        private_key = secret_key.to_hex()  # hex string
        public_key = secret_key.public_key.to_hex()
        with open("pvt.key", 'wb') as f:
            f.write(private_key.encode())
        f.close()
        with open("pri.key", 'wb') as f:
            f.write(public_key.encode())
        f.close()
    return private_key, public_key

#ECC will encrypt data using plain text adn public key
def ECCEncrypt(plainText, public_key):
    cpabe_encrypt = encrypt(public_key, plainText)
    return cpabe_encrypt

#ECC will decrypt data using private key and encrypted text
def ECCDecrypt(encrypt, private_key):
    cpabe_decrypt = decrypt(private_key, encrypt)
    return cpabe_decrypt

def Encode(src, message):
    global sender_sha
    img = Image.open(src, 'r')
    width, height = img.size
    array = np.array(list(img.getdata()))
    if img.mode == 'RGB':
        n = 3
    elif img.mode == 'RGBA':
        n = 4
    total_pixels = array.size//n
    message = message.encode()
    private_key, public_key = ECCGenerateKeys()
    ecc_encrypt = ECCEncrypt(message, public_key)
    sha = hashlib.sha256(ecc_encrypt)
    sender_sha = sha.hexdigest()
    tf2.insert(0, sender_sha)
    message = base64.b64encode(ecc_encrypt).decode()
    b_message = ''.join([format(ord(i), "08b") for i in message])
    req_pixels = len(b_message)
    if req_pixels > total_pixels:
        print("ERROR: Need larger file size")
    else:
        index=0
        for p in range(total_pixels):
            for q in range(0, 3):
                if index < req_pixels:
                    array[p][q] = int(bin(array[p][q])[2:9] + b_message[index], 2)
                    index += 1
        array=array.reshape(height, width, n)
        enc_img = Image.fromarray(array.astype('uint8'), img.mode)
        enc_img.save("ReceivedCompressImages/"+"Compressed_"+os.path.basename(src))
        with open("ReceivedCompressImages/"+"Compressed_"+os.path.basename(src), "rb") as file:
            data = file.read()
        file.close()
        huffmancompress = zlib.compress(data)
        with open("ReceivedCompressImages/"+"Compressed_"+os.path.basename(src), "wb") as file:
            file.write(huffmancompress)
        file.close()    
        text.insert(END,"ECC Cipher Text : "+str(message)+"\n")
        text.insert(END,'Compress Image Saved Inside "ReceivedCompressImages" folder\n')


def Decode(src):
    text.delete('1.0', END)                    
    with open(src, "rb") as file:
        data = file.read()
    file.close()
    data = zlib.decompress(data)
    with open("decompress.png", "wb") as file:
        file.write(data)
    file.close() 
    img = Image.open("decompress.png", 'r')
    array = np.array(list(img.getdata()))
    if img.mode == 'RGB':
        n = 3
    elif img.mode == 'RGBA':
        n = 4
    total_pixels = array.size//n

    hidden_bits = ""
    for p in range(total_pixels):
        for q in range(0, 3):
            hidden_bits += (bin(array[p][q])[2:][-1])
    hidden_bits = [hidden_bits[i:i+8] for i in range(0, len(hidden_bits), 8)]
    message = ""
    for i in range(len(hidden_bits)):
        if message[-5:] == "$t3g0":
            break
        else:
            message += chr(int(hidden_bits[i], 2))
    ecc_encrypt = base64.b64decode(message.encode())
    sha = hashlib.sha256(ecc_encrypt)
    sha = sha.hexdigest()
    text.insert(END,"Receiver Generated SHA code = "+sha+"\n")
    private_key, public_key = ECCGenerateKeys()
    decrypted = ECCDecrypt(ecc_encrypt, private_key)
    text.insert(END,"Extracted Hidden Secured Message = "+decrypted.decode()+"\n\n")
    text.update_idletasks()
    img.show()
    
def uploadSenderImage():
    global filename
    tf1.delete(0, END)
    tf2.delete(0, END)
    filename = filedialog.askopenfilename(initialdir="Images")
    text.delete('1.0', END)
    text.insert(END,filename+" loaded\n\n");
    
def sendImage():
    global filename, sender_sha
    text.delete('1.0', END)
    message = tf1.get()
    if len(message) < 6:
        message = message +"  "
    Encode(filename, message)
    
def decodeMessage():
    filename = filedialog.askopenfilename(initialdir="ReceivedCompressImages")
    text.delete('1.0', END)
    Decode(filename)

font = ('times', 15, 'bold')
title = Label(main, text='Securing data in the image using SHA & ECC')
title.config(bg='bisque', fg='purple1')  
title.config(font=font)           
title.config(height=3, width=120)       
title.place(x=0,y=5)

font1 = ('times', 13, 'bold')

uploadButton = Button(main, text="Upload Sender Side Image", command=uploadSenderImage)
uploadButton.place(x=50,y=100)
uploadButton.config(font=font1)

l1 = Label(main, text='Secret Message')
l1.config(font=font)
l1.place(x=50,y=150)

tf1 = Entry(main,width=50)
tf1.config(font=font)
tf1.place(x=220,y=150)

l2 = Label(main, text='Generated SHA')
l2.config(font=font)
l2.place(x=50,y=200)

tf2 = Entry(main,width=70)
tf2.config(font=font)
tf2.place(x=220,y=200)

sendButton = Button(main, text="Compress & Send Image", command=sendImage)
sendButton.place(x=50,y=250)
sendButton.config(font=font1)

decodeButton = Button(main, text="Receiver Upload & Decode Message", command=decodeMessage)
decodeButton.place(x=290,y=250)
decodeButton.config(font=font1)

font1 = ('times', 13, 'bold')
text=Text(main,height=20,width=120)
scroll=Scrollbar(text)
text.configure(yscrollcommand=scroll.set)
text.place(x=10,y=300)
text.config(font=font1)

main.config(bg='cornflower blue')
main.mainloop()
