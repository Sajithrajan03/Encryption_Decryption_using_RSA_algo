import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import zlib

# Global variables
private_key_rsa, public_key_rsa = None, None


def apply_pink_gradient(widget):
    style = ttk.Style()
    style.theme_use("default")

    # Define the pink gradient colors
    pink_gradient = ("#FFB6C1", "#FF69B4")

    # Configure the style for the widget with the pink gradient
    style.configure(widget, background=pink_gradient)


def select_input_file():
    filename = filedialog.askopenfilename()
    if filename:
        entry_input_file.delete(0, tk.END)
        entry_input_file.insert(tk.END, filename)


def compress_file():
    input_file = entry_input_file.get()
    if input_file:
        output_file = filedialog.asksaveasfilename(defaultextension=".compressed")
        if output_file:
            try:
                with open(input_file, 'rb') as file:
                    data = file.read()
                    compressed_data = zlib.compress(data, level=zlib.Z_BEST_COMPRESSION)
                with open(output_file, 'wb') as file:
                    file.write(compressed_data)
                messagebox.showinfo("Compression", f"File compressed and saved as: {output_file}")
            except IOError:
                messagebox.showerror("Compression Error", "Failed to compress the file.")


def decompress_file():
    input_file = entry_input_file.get()
    if input_file:
        output_file = filedialog.asksaveasfilename(defaultextension=".decompressed")
        if output_file:
            try:
                with open(input_file, 'rb') as file:
                    compressed_data = file.read()
                    decompressed_data = zlib.decompress(compressed_data)
                with open(output_file, 'wb') as file:
                    file.write(decompressed_data)
                messagebox.showinfo("Decompression", f"File decompressed and saved as: {output_file}")
            except IOError:
                messagebox.showerror("Decompression Error", "Failed to decompress the file.")


def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_message(public_key, message):
    encrypted_message = public_key.encrypt(
        message.encode('utf-8'),
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message


def decrypt_message(private_key, encrypted_message):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode('utf-8')


def encrypt_message_handler():
    message = text_input.get("1.0", tk.END).strip()
    if message:
        encrypted_message = encrypt_message(public_key_rsa, message)
        text_output.configure(state=tk.NORMAL)
        text_output.delete("1.0", tk.END)
        text_output.insert(tk.END, encrypted_message.hex())
        text_output.configure(state=tk.DISABLED)


def decrypt_message_handler():
    encrypted_message = text_input.get("1.0", tk.END).strip()
    if encrypted_message:
        try:
            encrypted_message = bytes.fromhex(encrypted_message)
            decrypted_message = decrypt_message(private_key_rsa, encrypted_message)
            text_output.configure(state=tk.NORMAL)
            text_output.delete("1.0", tk.END)
            text_output.insert(tk.END, decrypted_message)
            text_output.configure(state=tk.DISABLED)
        except ValueError:
            text_output.configure(state=tk.NORMAL)
            text_output.delete("1.0", tk.END)
            text_output.insert(tk.END, "Invalid input")
            text_output.configure(state=tk.DISABLED)


def save_key_to_json(private_key, public_key, filename):
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as file:
        file.write(private_pem + b'\n' + public_pem)


def save_keys_handler():
    private_key_file = filedialog.asksaveasfilename(defaultextension=".json")
    if private_key_file:
        save_key_to_json(private_key_rsa, public_key_rsa, private_key_file)
        messagebox.showinfo("Save Keys", "Keys saved successfully.")


def show_encryption():
    # Show the encryption widgets
    frame_encryption.pack()
    frame_compression.pack_forget()
    frame_decompression.pack_forget()

    # Update the navigation bar
    button_encryption.config(state=tk.DISABLED)
    button_compression.config(state=tk.NORMAL)
    button_decompression.config(state=tk.NORMAL)


def show_compression():
    # Show the compression widgets
    frame_encryption.pack_forget()
    frame_compression.pack()
    frame_decompression.pack_forget()

    # Update the navigation bar
    button_encryption.config(state=tk.NORMAL)
    button_compression.config(state=tk.DISABLED)
    button_decompression.config(state=tk.NORMAL)


def show_decompression():
    # Show the decompression widgets
    frame_encryption.pack_forget()
    frame_compression.pack_forget()
    frame_decompression.pack()

    # Update the navigation bar
    button_encryption.config(state=tk.NORMAL)
    button_compression.config(state=tk.NORMAL)
    button_decompression.config(state=tk.DISABLED)


# Create the main application window
window = tk.Tk()
window.title("Encryption and Compression Tool")

# Configure the window size and center it on the screen
window.geometry("600x400")
window.eval('tk::PlaceWindow . center')

# Configure the window background
apply_pink_gradient("TFrame")

# Create the navigation bar
frame_navbar = ttk.Frame(window, padding=10)
frame_navbar.pack(side="top", fill="x")

button_encryption = ttk.Button(frame_navbar, text="Encryption", command=show_encryption, state=tk.DISABLED)
button_encryption.pack(side="left")

button_compression = ttk.Button(frame_navbar, text="Compression", command=show_compression)
button_compression.pack(side="left")

button_decompression = ttk.Button(frame_navbar, text="Decompression", command=show_decompression)
button_decompression.pack(side="left")

# Create the encryption widgets
frame_encryption = ttk.Frame(window, padding=10)

private_key_rsa, public_key_rsa = generate_rsa_key_pair()

label_rsa_info = ttk.Label(frame_encryption, text="RSA Key Pair:")
label_rsa_info.pack()

button_save_keys = ttk.Button(frame_encryption, text="Save Keys", command=save_keys_handler)
button_save_keys.pack()

label_input = ttk.Label(frame_encryption, text="Input:")
label_input.pack()

text_input = tk.Text(frame_encryption, height=5)
text_input.pack()

label_output = ttk.Label(frame_encryption, text="Output:")
label_output.pack()

text_output = tk.Text(frame_encryption, height=5, state=tk.DISABLED)
text_output.pack()

button_encrypt = ttk.Button(frame_encryption, text="Encrypt", command=encrypt_message_handler)
button_encrypt.pack()

button_decrypt = ttk.Button(frame_encryption, text="Decrypt", command=decrypt_message_handler)
button_decrypt.pack()

# Create the compression widgets
frame_compression = ttk.Frame(window, padding=10)

label_input_file = ttk.Label(frame_compression, text="Input File:")
label_input_file.pack()

entry_input_file = ttk.Entry(frame_compression, width=50)
entry_input_file.pack()

button_select_file = ttk.Button(frame_compression, text="Select", command=select_input_file)
button_select_file.pack()

button_compress = ttk.Button(frame_compression, text="Compress", command=compress_file)
button_compress.pack()

# Create the decompression widgets
frame_decompression = ttk.Frame(window, padding=10)

label_input_file = ttk.Label(frame_decompression, text="Input File:")
label_input_file.pack()

entry_input_file = ttk.Entry(frame_decompression, width=50)
entry_input_file.pack()

button_select_file = ttk.Button(frame_decompression, text="Select", command=select_input_file)
button_select_file.pack()

button_decompress = ttk.Button(frame_decompression, text="Decompress", command=decompress_file)
button_decompress.pack()

# Show the encryption widgets by default
show_encryption()

# Start the main event loop
window.mainloop()
