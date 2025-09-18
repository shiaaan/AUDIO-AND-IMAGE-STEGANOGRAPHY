import numpy as np
import wave
import base64
import tkinter as tk
from PIL import Image
from tkinter import filedialog, messagebox, simpledialog,PhotoImage,Label
import moviepy as mp
from tkinter import ttk
from scipy.io.wavfile import read, write
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


class AudioSteganographyApp():
    def __init__(self, master):
        self.master = master
        master.title("Steganography Tools")
        master.geometry("500x500")

        # Create buttons for different steganography types
        self.audio_button = tk.Button(master, text="Audio Steganography", command=self.open_audio_window, width=40,height=5)
        self.audio_button.pack(pady=(70,10))

        self.image_button = tk.Button(master, text="Image Steganography", command=self.open_image_window,width=40,height=5)
        self.image_button.pack(pady=10)

        self.text_button = tk.Button(master, text="Text Steganography", command=self.open_text_window,width=40,height=5)
        self.text_button.pack(pady=10)

    def open_audio_window(self):
        self.open_steganography_window("Audio")

    def open_image_window(self):
        self.open_steganography_window("Image")

    def open_text_window(self):
        self.open_steganography_window("Text")

    def open_steganography_window(self, type):
        
        new_window = tk.Toplevel(self.master)
        # new_window.focus_force()
        new_window.title(f"{type} Steganography")
        new_window.geometry("600x400")
        
        
        # Create tabs
        self.tab_control = ttk.Notebook(new_window)
        self.encode_tab = ttk.Frame(self.tab_control)
        self.decode_tab = ttk.Frame(self.tab_control)
        self.image_encode_tab = ttk.Frame(self.tab_control)
        self.image_decode_tab = ttk.Frame(self.tab_control)
        self.text_encode_tab = ttk.Frame(self.tab_control)
        self.text_decode_tab = ttk.Frame(self.tab_control)

        
        # self.tab_control.pack(expand=1, fill="both")

        # Create tabs based on the type of steganography
        if type == "Audio":
            self.create_audio_encode_tab()
            self.create_audio_decode_tab()
        elif type == "Image":
            self.create_image_encode_tab()
            self.create_image_decode_tab()
        elif type == "Text":
            self.create_text_encode_tab()
            self.create_text_decode_tab()
        # self.create_video_decode_tab()

        # Generate RSA key pair
        self.generate_rsa_key_pair()
#create tabs.
    def create_audio_encode_tab(self):
        self.tab_control.add(self.encode_tab, text="Encode")
        self.tab_control.pack(expand=1, fill="both")
        
        self.encode_label = ttk.Label(self.encode_tab, text="Encode Message into Audio File", font=("Arial", 14))
        self.encode_label.pack(pady=10)

        self.message_label = ttk.Label(self.encode_tab, text="Message:")
        self.message_label.pack(pady=5)
        self.message_entry = ttk.Entry(self.encode_tab, width=50)
        self.message_entry.pack(pady=5)

        self.stego_key_label = ttk.Label(self.encode_tab, text="Stego Key:")
        self.stego_key_label.pack(pady=5)
        self.stego_key_entry = ttk.Entry(self.encode_tab, width=50)
        self.stego_key_entry.pack(pady=5)

        self.select_button = ttk.Button(self.encode_tab, text="Select WAV File", command=self.select_encode_file)
        self.select_button.pack(pady=10)
        
        self.encode_button = ttk.Button(self.encode_tab, text="Encode Message", command=self.encode_message)
        self.encode_button.pack(pady=10)
    def create_audio_decode_tab(self):
         
        self.tab_control.add(self.decode_tab, text="Decode")
        self.tab_control.pack(expand=1, fill="both")
        self.decode_label = ttk.Label(self.decode_tab, text="Decode Message from Audio File", font=("Arial", 14))
        self.decode_label.pack(pady=10)

        self.stego_key_label_decode = ttk.Label(self.decode_tab, text="Stego Key:")
        self.stego_key_label_decode.pack(pady=5)
        self.stego_key_entry_decode = ttk.Entry(self.decode_tab, width=50)
        self.stego_key_entry_decode.pack(pady=5)

        self.select_button_decode = ttk.Button(self.decode_tab, text="Select WAV File", command=self.select_decode_file)
        self.select_button_decode.pack(pady=10)
        
        self.decode_button = ttk.Button(self.decode_tab, text="Decode Message", command=self.decode_message)
        self.decode_button.pack(pady=10)
    def create_image_encode_tab(self):
        self.tab_control.add(self.image_encode_tab, text="Encode image")
        self.tab_control.pack(expand=1, fill="both")
        
        self.image_encode_label = ttk.Label(self.image_encode_tab, text="Encode Message into Image", font=("Arial", 14))
        self.image_encode_label.pack(pady=10)

        self.image_message_label = ttk.Label(self.image_encode_tab, text="Message:")
        self.image_message_label.pack(pady=5)
        self.image_message_entry = ttk.Entry(self.image_encode_tab, width=50)
        self.image_message_entry.pack(pady=5)

        self.image_stego_key_label = ttk.Label(self.image_encode_tab, text="Stego Key:")
        self.image_stego_key_label.pack(pady=5)
        self.image_stego_key_entry = ttk.Entry(self.image_encode_tab, width=50)
        self.image_stego_key_entry.pack(pady=5)

        self.select_image_button = ttk.Button(self.image_encode_tab, text="Select Image", command=self.select_image_encode_file)
        self.select_image_button.pack(pady=10)

        self.image_encode_button = ttk.Button(self.image_encode_tab, text="Encode Message", command=self.encode_image_message)
        self.image_encode_button.pack(pady=10)
    def create_image_decode_tab(self):
        self.tab_control.add(self.image_decode_tab, text="Decode image")
        self.tab_control.pack(expand=1, fill="both")
        self.image_decode_label = ttk.Label(self.image_decode_tab, text="Decode Message from Image", font=("Arial", 14))
        self.image_decode_label.pack(pady=10)

        self.image_stego_key_label_decode = ttk.Label(self.image_decode_tab, text="Stego Key:")
        self.image_stego_key_label_decode.pack(pady=5)
        self.image_stego_key_entry_decode = ttk.Entry(self.image_decode_tab, width=50)
        self.image_stego_key_entry_decode.pack(pady=5)

        self.select_image_button_decode = ttk.Button(self.image_decode_tab, text="Select Image", command=self.select_image_decode_file)
        self.select_image_button_decode.pack(pady=10)

        self.image_decode_button = ttk.Button(self.image_decode_tab, text="Decode Message", command=self.decode_image_message)
        self.image_decode_button.pack(pady=10)
    def create_text_encode_tab(self):
        self.tab_control.add(self.text_encode_tab, text="Encode text")
        self.tab_control.pack(expand=1, fill="both")
        
        self.text_encode_label = ttk.Label(self.text_encode_tab, text="Encode Message into Text File", font=("Arial", 14))
        self.text_encode_label.pack(pady=10)

        self.text_message_label = ttk.Label(self.text_encode_tab, text="Message:")
        self.text_message_label.pack(pady=5)
        self.text_message_entry = ttk.Entry(self.text_encode_tab, width=50)
        self.text_message_entry.pack(pady=5)

        self.text_stego_key_label = ttk.Label(self.text_encode_tab, text="Stego Key:")
        self.text_stego_key_label.pack(pady=5)
        self.text_stego_key_entry = ttk.Entry(self.text_encode_tab, width=50)
        self.text_stego_key_entry.pack(pady=5)

        self.select_text_button = ttk.Button(self.text_encode_tab, text="Select Text File", command=self.select_text_encode_file)
        self.select_text_button.pack(pady=10)

        self.text_encode_button = ttk.Button(self.text_encode_tab, text="Encode Message", command=self.encode_text_message)
        self.text_encode_button.pack(pady=10)
    def create_text_decode_tab(self):
        self.tab_control.add(self.text_decode_tab, text="Decode text")
        self.tab_control.pack(expand=1, fill="both")
        self.text_decode_label = ttk.Label(self.text_decode_tab, text="Decode Message from Text File", font=("Arial", 14))
        self.text_decode_label.pack(pady=10)

        self.text_stego_key_label_decode = ttk.Label(self.text_decode_tab, text="Stego Key:")
        self.text_stego_key_label_decode.pack(pady=5)
        self.text_stego_key_entry_decode = ttk.Entry(self.text_decode_tab, width=50)
        self.text_stego_key_entry_decode.pack(pady=5)

        self.select_text_button_decode = ttk.Button(self.text_decode_tab, text="Select Text File", command=self.select_text_decode_file)
        self.select_text_button_decode.pack(pady=10)

        self.text_decode_button = ttk.Button(self.text_decode_tab, text="Decode Message", command=self.decode_text_message)
        self.text_decode_button.pack(pady=10)
    
    
    
# audio encode and decode .
    def generate_rsa_key_pair(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

        # Save private key to a file
        with open("private_key.pem", "wb") as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Save public key to a file
        with open("public_key.pem", "wb") as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    def encrypt_stego_key(self, stego_key):
        with open("public_key.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        encrypted_key = public_key.encrypt(
            stego_key.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key

    def decrypt_stego_key(self, encrypted_key):
     try:
        # Load the private key from the file
        with open("private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,  # Adjust if the key is password-protected
                backend=default_backend(),
            )

        # Decrypt the key using the private key
        decrypted_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return decrypted_key.decode('utf-8')  # Convert bytes to string
     except Exception as e:
        messagebox.showerror("Error", f"Key decryption failed: {e}")
        return None

    def select_encode_file(self):
        self.encode_filepath = filedialog.askopenfilename(filetypes=[("WAV files", "*.wav")])
        if self.encode_filepath:
            messagebox.showinfo("Selected File", f"Selected file: {self.encode_filepath}")

    def select_decode_file(self):
        self.decode_filepath = filedialog.askopenfilename(filetypes=[("WAV files", "*.wav")])
        if self.decode_filepath:
            messagebox.showinfo("Selected File", f"Selected file: {self.decode_filepath}")

    def encode_message(self):
        if not hasattr(self, 'encode_filepath'):
            messagebox.showerror("Error", "Please select a WAV file first")
            return
        
        message = self.message_entry.get()
        key = self.stego_key_entry.get()
        if message and key:
            encrypted_key = self.encrypt_stego_key(key)
            self.lsb_encode(self.encode_filepath, message, encrypted_key)
        else:
            messagebox.showerror("Error", "Please enter both a message and a stego key")

    def decode_message(self):
        if not hasattr(self, 'decode_filepath'):
            messagebox.showerror("Error", "Please select a WAV file first")
            return

        key = self.stego_key_entry_decode.get()
        if key:
            encrypted_key, message = self.lsb_decode(self.decode_filepath)
            decrypted_key = self.decrypt_stego_key(encrypted_key)
            if decrypted_key == key:
                messagebox.showinfo("Success", f"Decoded message: {message}")
            else:
                messagebox.showerror("Error", "Incorrect stego key or no hidden message found")
        else:
            messagebox.showerror("Error", "Please enter the stego key")

    def lsb_encode(self, filepath, message, encrypted_key):
        audio = wave.open(filepath, mode='rb')
        frame_bytes = bytearray(list(audio.readframes(audio.getnframes())))

        message = encrypted_key + message.encode()
        message += int((len(frame_bytes) - (len(message) * 8 * 8)) / 8) * b'#'
        bits = list(map(int, ''.join([bin(byte).lstrip('0b').rjust(8, '0') for byte in message])))

        for i, bit in enumerate(bits):
            frame_bytes[i] = (frame_bytes[i] & 254) | bit

        frame_modified = bytes(frame_bytes)
        new_filepath = "encoded_audio.wav"
        with wave.open(new_filepath, 'wb') as fd:
            fd.setparams(audio.getparams())
            fd.writeframes(frame_modified)
        audio.close()

        messagebox.showinfo("Success", f"Message encoded successfully into {new_filepath}")

    def lsb_decode(self, filepath):
        audio = wave.open(filepath, mode='rb')
        frame_bytes = bytearray(list(audio.readframes(audio.getnframes())))

        extracted_bits = [frame_bytes[i] & 1 for i in range(len(frame_bytes))]
        extracted_bytes = [int(''.join(map(str, extracted_bits[i:i+8])), 2) for i in range(0, len(extracted_bits), 8)]
        extracted_message = bytes(extracted_bytes).split(b"###")[0]

        encrypted_key_length = 256  # 2048 bits / 8 bits per byte
        encrypted_key = extracted_message[:encrypted_key_length]
        message = extracted_message[encrypted_key_length:].decode()

        audio.close()
        return encrypted_key, message
 #end of audio encode and decode.


#start of image encode and decode.
    def select_image_encode_file(self):
        self.image_encode_filepath = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.bmp")])
        if self.image_encode_filepath:
            messagebox.showinfo("Selected File", f"Selected file: {self.image_encode_filepath}")

    def select_image_decode_file(self):
        self.image_decode_filepath = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.bmp")])
        if self.image_decode_filepath:
            messagebox.showinfo("Selected File", f"Selected file: {self.image_decode_filepath}")

    def encode_image_message(self):
        if not hasattr(self, 'image_encode_filepath'):
            messagebox.showerror("Error", "Please select an image file first")
            return

        message = self.image_message_entry.get()
        key = self.image_stego_key_entry.get()
        if message and key:
            encrypted_key = self.encrypt_stego_key(key)
            self.image_lsb_encode(self.image_encode_filepath, message, encrypted_key)
        else:
            messagebox.showerror("Error", "Please enter both a message and a stego key")

    def decode_image_message(self):
        if not hasattr(self, 'image_decode_filepath'):
            messagebox.showerror("Error", "Please select an image file first")
            return

        key = self.image_stego_key_entry_decode.get()
        if key:
            encrypted_key, message = self.image_lsb_decode(self.image_decode_filepath)
            decrypted_key = self.decrypt_stego_key(encrypted_key)
            if decrypted_key == key:
                messagebox.showinfo("Success", f"Decoded message: {message}")
            else:
                messagebox.showerror("Error", "Incorrect stego key or no hidden message found")
        else:
            messagebox.showerror("Error", "Please enter the stego key")

    def image_lsb_encode(self, filepath, message, encrypted_key):
        img = Image.open(filepath)
        img = img.convert("RGB")  # Ensure the image is in RGB format
        pixels = np.array(img).flatten()

        data = encrypted_key + message.encode()
        data += b"###"  # Delimiter for the end of the hidden message
        data_bits = list(map(int, ''.join(bin(byte)[2:].zfill(8) for byte in data)))

        if len(data_bits) > len(pixels):
            messagebox.showerror("Error", "Message is too large to encode in the selected image")
            return

        # Encode message bits into the pixel data
        for i, bit in enumerate(data_bits):
            pixels[i] = (pixels[i] & 0xFE) | bit  # Clear the least significant bit and set it to the message bit

        # Reshape the modified pixels array to the original image dimensions
        encoded_pixels = pixels.reshape(img.size[1], img.size[0], -1)
        encoded_img = Image.fromarray(encoded_pixels.astype('uint8'))

        new_filepath = "encoded_image.png"
        encoded_img.save(new_filepath)
        messagebox.showinfo("Success", f"Message encoded successfully into {new_filepath}")

    def image_lsb_decode(self, filepath):
        img = Image.open(filepath)
        img = img.convert("RGB")  # Ensure the image is in RGB format
        pixels = np.array(img).flatten()

        bits = [pixels[i] & 1 for i in range(len(pixels))]
        extracted_bytes = [int(''.join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits), 8)]
        extracted_message = bytes(extracted_bytes).split(b"###")[0]

        encrypted_key_length = 256  # 2048 bits / 8 bits per byte
        encrypted_key = extracted_message[:encrypted_key_length]
        message = extracted_message[encrypted_key_length:].decode('utf-8', errors='ignore')


        return encrypted_key, message
#end of image encode and decode

#start of text encode and decode.
    def select_text_encode_file(self):
        self.text_encode_filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if self.text_encode_filepath:
            messagebox.showinfo("Selected File", f"Selected file: {self.text_encode_filepath}")
    def select_text_decode_file(self):

        self.text_decode_filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if self.text_decode_filepath:
            messagebox.showinfo("Selected File", f"Selected file: {self.text_decode_filepath}")
    def encode_text_message(self):
        if not hasattr(self, 'text_encode_filepath'):
            messagebox.showerror("Error", "Please select a text file first")
            return

        message = self.text_message_entry.get()
        key = self.text_stego_key_entry.get()
        if message and key:
            encrypted_key = self.encrypt_stego_key(key)
            self.lsb_encode_text(self.text_encode_filepath, message, encrypted_key)
        else:
            messagebox.showerror("Error", "Please enter both a message and a stego key")

    # def select_text_decode_file(self):
    #     self.text_decode_filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    #     if self.text_decode_filepath:
    #         messagebox.showinfo("Selected File", f"Selected file: {self.text_decode_filepath}")

    def decode_text_message(self):
        if not hasattr(self, 'text_decode_filepath'):
            messagebox.showerror("Error", "Please select a text file first")
            return

        key = self.text_stego_key_entry_decode.get()
        if key:
            encrypted_key, message = self.lsb_decode_text(self.text_decode_filepath)
            decrypted_key = self.decrypt_stego_key(encrypted_key)
            if decrypted_key == key:
                messagebox.showinfo("Success", f"Decoded message: {message}")
            else:
                messagebox.showerror("Error", "Incorrect stego key or no hidden message found")
        else:
            messagebox.showerror("Error", "Please enter the stego key")

            return encrypted_key, message

    # def lsb_encode_text(self, filepath, message, encrypted_key):
    #     with open(filepath, 'r') as file:
    #         content = file.read()

    # # Encode the encrypted key in base64
    #     encrypted_key_b64 = base64.b64encode(encrypted_key).decode('utf-8')

    # # Append the base64-encoded encrypted key and the message
    #     new_content = content + "\n" + encrypted_key_b64 + "\n" + message

    #     new_filepath = "encoded_text.txt"
    #     with open(new_filepath, 'w') as file:
    #         file.write(new_content)

    #     messagebox.showinfo("Success", f"Message encoded successfully into {new_filepath}")

    # def lsb_decode_text(self, filepath):
    #     with open(filepath, 'r') as file:
    #         content = file.read().splitlines()

    # # Assuming the last two lines contain the base64-encoded encrypted key and the message
    #     encrypted_key_b64 = content[-2]  # Second to last line
    #     message = content[-1]  # Last line

    # # Decode the base64-encoded encrypted key
    #     encrypted_key = base64.b64decode(encrypted_key_b64)

    #     return encrypted_key, message
#end of text encode and decode.








root = tk.Tk()
app = AudioSteganographyApp(root)
root.mainloop()






   