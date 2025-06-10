import argparse
import base64
from enum import Enum

import tkinter as tk
from os import write
from tkinter import filedialog, messagebox
from tkinter import ttk
from unittest import case

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def main():
    parser = argparse.ArgumentParser(description='Encrypt or decrypt a string using a selected mode.')

    parser.add_argument('-s', '--string', type=str, help='Input string')
    parser.add_argument('-e', '--encode', action='store_true', help='Encode the input string')
    parser.add_argument('-d', '--decode', action='store_true', help='Decode the input string')
    parser.add_argument('--iv', type=str, help='16-byte initialization vector (required for decode)')
    parser.add_argument('--key', type=str, help='AES Key')
    parser.add_argument('--mode', type=str, choices=['CBC', 'CTR', 'GCM'], default='CBC', help='Encryption mode (default: CBC)')
    parser.add_argument('-v', '--visual', action='store_true', help='Start Visual Editor')

    args = parser.parse_args()

    if args.visual:
        root = tk.Tk()
        app = Gui(root)
        root.mainloop()
    else:
        if not args.encode and not args.decode:
            parser.error("You must specify either --encode or --decode.")

        if args.encode and args.decode:
            parser.error("You cannot specify both --encode and --decode.")

        if args.decode and not (args.iv or args.key):
            parser.error("Missing IV or Key")

        input_string = args.string
        iv = read_b64(args.iv) if args.iv else None
        key = read_b64(args.key) if args.key else None
        mode = args.mode

        if args.encode:
            print(f"[Encoding] String: {input_string}")
            print(f"Mode: {mode}")
            iv = iv_gen()
            key = key_gen()
            data = pad_data(input_string.encode('utf-8'))
            match mode:
                case 'CBC':
                    ciphertext = cbc_encrypt(data, key, iv)
                    print(f"Ciphertext (base64): {print_b64(ciphertext)}")
                case 'CTR':
                    pass
                case 'GCM':
                    pass
            print(f"IV : {print_b64(iv)}")
            print(f"Key: {print_b64(key)}")
        elif args.decode:
            ciphertext = read_b64(input_string)
            data = pad_data(ciphertext)
            plaintext = cbc_decrypt(data, key, iv)
            print(f"Decrypted: {plaintext}")


class Mode(Enum):
    CBC = "CBC"
    CTR = "CTR"
    GCM = "GCM"

def key_gen():
    return os.urandom(32)

def iv_gen():
    return os.urandom(16)

def pad_data(plaintext):
    padder = padding.PKCS7(128).padder()
    return padder.update(plaintext) + padder.finalize()

def print_b64(raw):
    return base64.b64encode(raw).decode('utf-8')

def read_b64(b64):
    return base64.b64decode(b64.encode('utf-8'))

def cbc_encrypt(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def cbc_decrypt(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()



class Gui:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Encryption/Decryption Tool")

        # Input File
        self.input_file_path = tk.StringVar()
        tk.Label(root, text="Input File:").grid(row=0, column=0, sticky="e")
        tk.Entry(root, textvariable=self.input_file_path, width=50).grid(row=0, column=1)
        tk.Button(root, text="Browse...", command=self.load_input_file).grid(row=0, column=2)

        # Input Text
        tk.Label(root, text="Input Text:").grid(row=1, column=0, sticky="ne")
        self.input_text = tk.Text(root, height=10, width=60)
        self.input_text.grid(row=1, column=1, columnspan=2)

        # Mode Dropdown
        tk.Label(root, text="Mode:").grid(row=2, column=0, sticky="e")
        self.mode_var = tk.StringVar(value=Mode.CBC.value)
        ttk.Combobox(root, textvariable=self.mode_var,
                     values=[m.value for m in Mode], state="readonly").grid(row=2, column=1, sticky="w")

        # AES Key
        self.key_var = tk.StringVar()
        tk.Label(root, text="AES Key (base64):").grid(row=3, column=0, sticky="e")
        tk.Entry(root, textvariable=self.key_var, width=50).grid(row=3, column=1, columnspan=2)

        # Initialization Vector
        self.iv_var = tk.StringVar()
        tk.Label(root, text="Initialization Vector (base64):").grid(row=4, column=0, sticky="e")
        tk.Entry(root, textvariable=self.iv_var, width=50).grid(row=4, column=1, columnspan=2)

        # Buttons for Encrypt / Decrypt
        tk.Button(root, text="Encrypt", command=self.encrypt).grid(row=5, column=1, pady=10, sticky="e")
        tk.Button(root, text="Decrypt", command=self.decrypt).grid(row=5, column=2, pady=10, sticky="w")

        # Output Text
        tk.Label(root, text="Output Text:").grid(row=6, column=0, sticky="ne")
        self.output_text = tk.Text(root, height=10, width=60)
        self.output_text.grid(row=6, column=1, columnspan=2)

        # Save Output
        tk.Button(root, text="Save Output...", command=self.save_output_file).grid(row=7, column=2, pady=10)

    def load_input_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.input_file_path.set(path)
            with open(path, 'r', encoding='utf-8') as f:
                data = f.read()
            self.input_text.delete('1.0', tk.END)
            self.input_text.insert(tk.END, data)

    def save_output_file(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if path:
            data = self.output_text.get('1.0', tk.END)
            with open(path, 'w', encoding='utf-8') as f:
                f.write(data)
            messagebox.showinfo("Saved", f"Output saved to {path}")

    def get_key_iv(self):
        # Generate key/iv if not provided
        key_b64 = self.key_var.get().strip()
        iv_b64 = self.iv_var.get().strip()
        key = read_b64(key_b64) if key_b64 else key_gen()
        iv = read_b64(iv_b64) if iv_b64 else iv_gen()
        # Update fields with generated hex if empty
        if not key_b64:
            self.key_var.set(print_b64(key))
        if not key_b64:
            self.iv_var.set(print_b64(iv))
        return key, iv

    def encrypt(self):
        mode = self.mode_var.get()
        plaintext = self.input_text.get('1.0', tk.END)
        key, iv = self.get_key_iv()

        data = pad_data(plaintext.encode('utf-8'))

        ciphertext:bytes
        match mode:
            case 'CBC':
                ciphertext = cbc_encrypt(data, key, iv)
            case 'CTR':
                pass
            case 'GCM':
                pass

        self.output_text.delete('1.0', tk.END)
        self.output_text.insert(tk.END, print_b64(ciphertext))
        messagebox.showinfo("Done", "Encryption completed.")

    def decrypt(self):
        mode = self.mode_var.get()
        ciphertext = read_b64(self.input_text.get('1.0', tk.END))

        key, iv = self.get_key_iv()

        data = pad_data(ciphertext)

        plaintext: bytes
        match mode:
            case 'CBC':
                plaintext = cbc_decrypt(data, key, iv)
            case 'CTR':
                pass
            case 'GCM':
                pass

        self.output_text.delete('1.0', tk.END)
        self.output_text.insert(tk.END, plaintext)
        messagebox.showinfo("Done", "Decryption completed.")



if __name__ == '__main__':
    main()