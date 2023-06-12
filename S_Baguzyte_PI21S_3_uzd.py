# 3 praktine uzuodis: RSA algoritmo šifravimo/dešifravimo sistema
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

# Euklido algoritmas didziausio bendro daliklio radimui
def greatest_common_divisor(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Euklido isplestinis algoritmas modulinio atvirkstinio radimui
def modular_inverse(a, b):
    if a == 0:
        return b, 0, 1
    else:
        greatest_common_divisor, x, y = modular_inverse(b % a, a)
        return greatest_common_divisor, y - (b // a) * x, x

def generate_keys(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 2
    while e < phi:
        if greatest_common_divisor(e, phi) == 1:
            break
        e += 1
    _, d, _ = modular_inverse(e, phi)
    if d < 0:
        d += phi
    return (n, e), (n, d)

def save_keys(public_key):
    n, e = public_key
    key_data = f"Public Key (n, e):\n{n}\n{e}"
    file_path = filedialog.asksaveasfilename(defaultextension=".txt")
    with open(file_path, 'w') as file:
        file.write(key_data)

def load_keys():
    file_path = filedialog.askopenfilename(filetypes=[('Text Files', '*.txt')])
    with open(file_path, 'r') as file:
        key_data = file.read()
    n, e = key_data.split('\n')[1:3]
    return int(n), int(e)

# ivedineti is konsoles
def generate_prime_numbers():
    return 101, 103

def encryption(public_key, message):
    n, e = public_key
    encrypted_message = [pow(ord(char), e, n) for char in message]
    return encrypted_message

def encrypt_text():
    text = input_text.get("1.0", tk.END).strip()
    if len(text) == 0:
        messagebox.showerror("Error", "Please, enter text to encrypt.")
        return
    p, q = generate_prime_numbers()
    public_key, _ = generate_keys(p, q)
    encrypted_message = encryption(public_key, text)
    save_keys(public_key)
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, encrypted_message)

def decryption(private_key, encrypted_message):
    n, d = private_key
    decrypted_message = [chr(pow(char, d, n)) for char in encrypted_message]
    return ''.join(decrypted_message)

def decrypt_text():
    public_key = load_keys()
    if public_key is None:
        return
    file_path = filedialog.askopenfilename(filetypes=[('Text Files', '*.txt')])
    if not file_path:
        return
    with open(file_path, 'rb') as file:
        encrypted_message = file.read()
    if len(encrypted_message) == 0:
        messagebox.showerror("Error", "The selected file is empty.")
        return
    encrypted_message = encrypted_message.strip().split()
    decrypted_message = decryption(public_key, list(map(int, encrypted_message)))
    try:
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decrypted_message)
    except UnicodeDecodeError:
        messagebox.showerror("Error", "Invalid characters in the encrypted message.")

window = tk.Tk()
window.title("RSA Encryption/Decryption")

label_input = tk.Label(window, text="Input Text:")
label_input.pack()
input_text = tk.Text(window, height=5)
input_text.pack()

button_encrypt = tk.Button(window, text="Encrypt", command=encrypt_text)
button_encrypt.pack()

button_decrypt = tk.Button(window, text="Decrypt", command=decrypt_text)
button_decrypt.pack()

label_output = tk.Label(window, text="Output Text:")
label_output.pack()
output_text = tk.Text(window, height=5)
output_text.pack()

window.mainloop()