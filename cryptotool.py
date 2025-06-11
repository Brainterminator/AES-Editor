import argparse
import base64
import binascii
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from enum import Enum
import os

# Cryptography library imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag


# --- Constants and Enums ---

class Mode(Enum):
    """Enumeration for the different AES modes."""
    CBC = "CBC"
    CTR = "CTR"
    GCM = "GCM"


# --- Core Cryptographic Logic ---

class CryptoEngine:
    """Handles all encryption and decryption operations."""

    def __init__(self, mode: Mode, key: bytes, iv: bytes):
        if mode not in Mode:
            raise ValueError("Unsupported mode")
        self.mode = mode
        self.key = key
        self.iv = iv
        self.backend = default_backend()

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypts plaintext based on the selected mode."""
        # GCM and CTR are stream ciphers and do not use padding.
        if self.mode == Mode.CBC:
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(plaintext) + padder.finalize()
        else:
            padded_data = plaintext

        algorithm = algorithms.AES(self.key)
        cipher_mode = self._get_cipher_mode()
        cipher = Cipher(algorithm, cipher_mode, backend=self.backend)
        encryptor = cipher.encryptor()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # For GCM, append the authentication tag to the ciphertext
        if self.mode == Mode.GCM:
            return ciphertext + encryptor.tag

        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypts ciphertext based on the selected mode."""
        tag = None
        # For GCM, extract the tag from the end of the ciphertext
        if self.mode == Mode.GCM:
            tag = ciphertext[-16:]
            ciphertext = ciphertext[:-16]

        algorithm = algorithms.AES(self.key)
        cipher_mode = self._get_cipher_mode(tag)
        cipher = Cipher(algorithm, cipher_mode, backend=self.backend)
        decryptor = cipher.decryptor()

        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

        # CBC is the only mode here that uses padding.
        if self.mode == Mode.CBC:
            try:
                unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
                return unpadder.update(decrypted_padded) + unpadder.finalize()
            except Exception:
                print("Corrupted Padding detected!")

        return decrypted_padded

    def _get_cipher_mode(self, tag=None):
        """Helper to get the correct mode instance from the cryptography library."""
        if self.mode == Mode.CBC:
            return modes.CBC(self.iv)
        if self.mode == Mode.CTR:
            return modes.CTR(self.iv)
        if self.mode == Mode.GCM:
            return modes.GCM(self.iv, tag)
        raise ValueError(f"Internal error: Mode {self.mode.value} not implemented in _get_cipher_mode")


# --- Helper Functions ---

def key_gen() -> bytes:
    """Generates a secure 256-bit (32-byte) AES key."""
    return os.urandom(32)


def iv_gen() -> bytes:
    """Generates a secure 128-bit (16-byte) Initialization Vector."""
    return os.urandom(16)


def bytes_to_hex(data: bytes) -> str:
    """Converts bytes to a hex string."""
    return data.hex()


def hex_to_bytes(hex_str: str) -> bytes:
    """Converts a hex string to bytes."""
    return bytes.fromhex(hex_str)


# --- Graphical User Interface ---

class Gui:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Encryption/Decryption Tool")
        self._setup_widgets()

    def _setup_widgets(self):
        # Configure grid
        self.root.columnconfigure(1, weight=1)

        # Input File
        tk.Label(self.root, text="Input File:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.input_file_path = tk.StringVar()
        tk.Entry(self.root, textvariable=self.input_file_path, width=50).grid(row=0, column=1, sticky="ew")
        tk.Button(self.root, text="Browse...", command=self.load_input_file).grid(row=0, column=2, padx=5)

        # Input Text
        tk.Label(self.root, text="Input Text:").grid(row=1, column=0, sticky="nw", padx=5, pady=2)
        self.input_text = tk.Text(self.root, height=8, width=60)
        self.input_text.grid(row=1, column=1, columnspan=2, sticky="ew", padx=5)

        # Mode Dropdown
        tk.Label(self.root, text="Mode:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.mode_var = tk.StringVar(value=Mode.CBC.value)
        ttk.Combobox(self.root, textvariable=self.mode_var,
                     values=[m.value for m in Mode], state="readonly").grid(row=2, column=1, sticky="w", padx=5)

        # AES Key
        tk.Label(self.root, text="AES Key (hex):").grid(row=3, column=0, sticky="w", padx=5, pady=2)
        self.key_var = tk.StringVar()
        tk.Entry(self.root, textvariable=self.key_var, width=50).grid(row=3, column=1, columnspan=2, sticky="ew",
                                                                      padx=5)

        # Initialization Vector
        tk.Label(self.root, text="IV/Nonce (hex):").grid(row=4, column=0, sticky="w", padx=5, pady=2)
        self.iv_var = tk.StringVar()
        tk.Entry(self.root, textvariable=self.iv_var, width=50).grid(row=4, column=1, columnspan=2, sticky="ew", padx=5)

        # Buttons Frame
        button_frame = tk.Frame(self.root)
        button_frame.grid(row=5, column=1, columnspan=2, pady=10, sticky="e")
        tk.Button(button_frame, text="Encrypt", command=self.encrypt).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Decrypt", command=self.decrypt).pack(side=tk.LEFT)

        # Output Text
        tk.Label(self.root, text="Output Text:").grid(row=6, column=0, sticky="nw", padx=5, pady=2)
        self.output_text = tk.Text(self.root, height=8, width=60)
        self.output_text.grid(row=6, column=1, columnspan=2, sticky="ew", padx=5)

        # Save Output Button
        tk.Button(self.root, text="Save Output...", command=self.save_output_file).grid(row=7, column=2, pady=5, padx=5,
                                                                                        sticky="e")

    def load_input_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.input_file_path.set(path)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = f.read()
                self.input_text.delete('1.0', tk.END)
                self.input_text.insert(tk.END, data)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read file: {e}")

    def save_output_file(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            data = self.output_text.get('1.0', tk.END).strip()
            with open(path, 'w', encoding='utf-8') as f:
                f.write(data)
            messagebox.showinfo("Saved", f"Output saved to {path}")

    def _get_and_validate_inputs(self, is_encrypt: bool):
        """Gets and validates all inputs from the GUI fields."""
        mode = Mode(self.mode_var.get())

        key_hex = self.key_var.get().strip()
        iv_hex = self.iv_var.get().strip()

        # Generate key/iv for encryption if not provided
        if is_encrypt:
            if not key_hex:
                key = key_gen()
                self.key_var.set(bytes_to_hex(key))
            else:
                key = hex_to_bytes(key_hex)

            if not iv_hex:
                iv = iv_gen()
                self.iv_var.set(bytes_to_hex(iv))
            else:
                iv = hex_to_bytes(iv_hex)
        else:  # For decryption, key and iv are required
            if not key_hex or not iv_hex:
                raise ValueError("Key and IV are required for decryption.")
            key = hex_to_bytes(key_hex)
            iv = hex_to_bytes(iv_hex)

        return mode, key, iv

    def encrypt(self):
        try:
            mode, key, iv = self._get_and_validate_inputs(is_encrypt=True)
            engine = CryptoEngine(mode, key, iv)

            plaintext = self.input_text.get('1.0', tk.END).strip().encode('utf-8')
            ciphertext = engine.encrypt(plaintext)

            self.output_text.delete('1.0', tk.END)
            self.output_text.insert(tk.END, bytes_to_hex(ciphertext))
            messagebox.showinfo("Success", "Encryption complete.")
        except Exception as e:
            messagebox.showerror("Encryption Error", f"An error occurred: {e}")

    def decrypt(self):
        try:
            mode, key, iv = self._get_and_validate_inputs(is_encrypt=False)
            engine = CryptoEngine(mode, key, iv)

            ciphertext_hex = self.input_text.get('1.0', tk.END).strip()
            ciphertext = hex_to_bytes(ciphertext_hex)

            plaintext = engine.decrypt(ciphertext)

            self.output_text.delete('1.0', tk.END)
            self.output_text.insert(tk.END, plaintext.decode('utf-8', errors='replace'))
            messagebox.showinfo("Success", "Decryption complete.")
        except InvalidTag:
            messagebox.showerror("Decryption Error",
                                 "Decryption failed: The data may have been tampered with (GCM authentication failed).")
        except Exception as e:
            messagebox.showerror("Decryption Error",
                                 f"An error occurred: {e}\n\nCheck if the key, IV, and ciphertext are correct.")


def patch_ciphertext(ciphertext: bytes, old: bytes, new: bytes, offset: int = 0) -> bytes:
    if len(old) != len(new):
        raise ValueError("Old and new plaintext segments must be the same length.")

    patched = bytearray(ciphertext)
    for i in range(len(old)):
        patched[offset + i] ^= old[i] ^ new[i]
    return bytes(patched)

def auto_decode(input_str: str) -> bytes:
    """Attempts to decode input as hex first, then base64."""
    try:
        return bytes.fromhex(input_str)
    except ValueError:
        try:
            return base64.b64decode(input_str)
        except (binascii.Error, ValueError):
            raise ValueError("Input string is not valid hex or base64.")

# --- Command-Line Interface ---

def main_cli():
    parser = argparse.ArgumentParser(description='Encrypt or decrypt a string using AES.')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encrypt', action='store_true', help='Encrypt the input string.')
    group.add_argument('-d', '--decrypt', action='store_true', help='Decrypt the input string.')
    group.add_argument('--modify-cipher', action='store_true',
                        help='Modify ciphertext given old and new plaintext segments.')

    parser.add_argument('-s', '--string', type=str, required=True, help='Input string or ciphertext (in hex).')
    parser.add_argument('--key', type=str,
                        help='32-byte (64 hex chars) AES Key. Generated if not provided for encryption.')
    parser.add_argument('--iv', type=str, help='16-byte (32 hex chars) IV. Generated if not provided for encryption.')
    parser.add_argument('--mode', type=str, choices=[m.value for m in Mode], default=Mode.CBC.value,
                        help='Encryption mode.')
    parser.add_argument('-v', '--visual', action='store_true', help='Start the visual editor instead of using the CLI.')
    parser.add_argument('--old-plain', type=str, help='Known plaintext originally in the ciphertext.')
    parser.add_argument('--new-plain', type=str, help='Desired plaintext to substitute in ciphertext.')
    parser.add_argument('-o', '--offset', type=int, help='Offset for cipher modification')

    args = parser.parse_args()

    if args.modify_cipher:
        if not args.old_plain or not args.new_plain:
            parser.error("--old-plain and --new-plain are required when using --modify-cipher.")

        if not args.offset:
            args.offset = 0

        old_bytes = args.old_plain.encode('utf-8')
        new_bytes = args.new_plain.encode('utf-8')
        ciphertext = auto_decode(args.string)

        modified_cipher = patch_ciphertext(ciphertext, old_bytes, new_bytes, offset=args.offset)  # optionally allow offset param
        print(f"Original Ciphertext: {args.string}")
        print(f"Modified Ciphertext: {base64.b64encode(modified_cipher).decode('utf-8', errors='replace')}")
        return

    # If visual mode is requested, start GUI and ignore other args
    if args.visual:
        root = tk.Tk()
        Gui(root)
        root.mainloop()
        return

    # --- CLI Logic ---
    try:
        mode = Mode(args.mode)

        # Handle Key and IV
        if args.encrypt:
            key = hex_to_bytes(args.key) if args.key else key_gen()
            iv = hex_to_bytes(args.iv) if args.iv else iv_gen()
        else:  # Decrypt
            if not args.key or not args.iv:
                parser.error("--key and --iv are required for decryption.")
            key = hex_to_bytes(args.key)
            iv = hex_to_bytes(args.iv)

        engine = CryptoEngine(mode, key, iv)

        print(f"Mode: {mode.value}")
        print(f"Key (hex): {bytes_to_hex(key)}")
        print(f"IV (hex):  {bytes_to_hex(iv)}")
        print("-" * 20)

        if args.encrypt:
            plaintext = args.string.encode('utf-8')
            ciphertext = engine.encrypt(plaintext)
            print(f"Plaintext:  {args.string}")
            print(f"Ciphertext (hex): {bytes_to_hex(ciphertext)}")
        else:  # Decrypt
            ciphertext = hex_to_bytes(args.string)
            plaintext = engine.decrypt(ciphertext)
            print(f"Ciphertext (hex): {args.string}")
            print(f"Plaintext:  {plaintext.decode('utf-8')}")

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == '__main__':
    # Check if any argument is passed. If '-v' or '--visual' is passed, or if no arguments are passed, show GUI.
    # Otherwise, proceed with CLI. This makes the GUI the default "double-click" action.
    import sys

    if '-v' in sys.argv or '--visual' in sys.argv:
        root = tk.Tk()
        Gui(root)
        root.mainloop()
    elif len(sys.argv) > 1:
        main_cli()
    else:  # Default to GUI if no args
        root = tk.Tk()
        Gui(root)
        root.mainloop()