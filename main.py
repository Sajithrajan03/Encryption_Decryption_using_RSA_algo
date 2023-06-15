from PyQt5.QtWidgets import QApplication, QMainWindow, QFrame, QLabel, QLineEdit, QPushButton, QTextEdit, QFileDialog, QMessageBox
from PyQt5.QtCore import Qt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import zlib
import json


class EncryptionCompressionTool(QMainWindow):



    def __init__(self):
        super().__init__()
        self.private_key_rsa, self.public_key_rsa = self.generate_rsa_key_pair()

        self.setWindowTitle("Encryption and Compression Tool")
        self.setGeometry(100, 100, 1000, 900)
        self.setStyleSheet("background-color: #97d5f0; font-weight: bold; ")
        self.create_widgets()
        self.show_encryption()
        
    def create_widgets(self):
        self.frame = QFrame(self)
        self.setCentralWidget(self.frame)

        self.button_encryption = QPushButton("Encryption", self.frame)
        self.button_encryption.setGeometry(120, 10, 160, 60)
        self.button_encryption.setCursor(Qt.PointingHandCursor)
        self.button_encryption.setCheckable(True)
        self.button_encryption.setStyleSheet("""
       QPushButton {
            background-color: #f25060;
        font-weight: bold;
        font-size: 20px;
        border: 2px solid black;
        border-radius: 15px;
        }
        QPushButton:hover {
        
        font-weight: bold;
        font-size: 20px;
        border: 2px solid black;
        border-radius: 15px;
        background-color: lightgreen;
        }
        QPushButton:checked {
        font-weight: bold;
        font-size: 20px;
        border: 2px solid black;
        border-radius: 15px;
        
    }
        """)


        self.button_encryption.clicked.connect(self.show_encryption)

        self.button_compression = QPushButton("Compression", self.frame)
        self.button_compression.setGeometry(400, 10, 180, 60)
        self.button_compression.setCursor(Qt.PointingHandCursor)
        self.button_compression.setStyleSheet("""
        QPushButton {
            background-color: #f25060;
        font-weight: bold;
        font-size: 20px;
        border: 2px solid black;
        border-radius: 15px;
        }
        QPushButton:hover {
        
        font-weight: bold;
        font-size: 20px;
        border: 2px solid black;
        border-radius: 15px;
        background-color: lightgreen;
        }
        QPushButton:checked {
        font-weight: bold;
        font-size: 20px;
        border: 2px solid black;
        border-radius: 15px;
        
        background-color: green;
    }
        """)
        self.button_compression.clicked.connect(self.show_compression)

        self.button_decompression = QPushButton("Decompression", self.frame)
        self.button_decompression.setGeometry(680, 10, 220, 60)
        self.button_decompression.setCursor(Qt.PointingHandCursor)
        self.button_decompression.setStyleSheet("""
        QPushButton {
            background-color: #f25060;
        font-weight: bold;
        font-size: 20px;
        border: 2px solid black;
        border-radius: 15px;
        }
        QPushButton:hover {
        
        font-weight: bold;
        font-size: 20px;
        border: 2px solid black;
        border-radius: 15px;
        background-color: lightgreen;
        }
        QPushButton:checked {
        font-weight: bold;
        font-size: 20px;
        border: 2px solid black;
        border-radius: 15px;
        
        background-color: green;
    }
        """)
        self.button_decompression.clicked.connect(self.show_decompression)

        # Encryption Widgets
        self.frame_encryption = QFrame(self.frame)
        self.frame_encryption.setGeometry(10, 80, 980, 710)
        self.frame_encryption.hide()

        label_rsa_info = QLabel("RSA Key Pair:", self.frame_encryption)
        label_rsa_info.setGeometry(10, 10, 120, 40)
        label_rsa_info.setStyleSheet("font-weight: bold; font-size: 18px;")

        button_save_keys = QPushButton("Save Keys", self.frame_encryption)
        button_save_keys.setCursor(Qt.PointingHandCursor)
        button_save_keys.setGeometry(10, 60, 160, 40)
        button_save_keys.setStyleSheet("""
        background-color: #FAF26C;
        font-weight: bold;
        border: 2px solid black;
        border-radius: 15px;
        QPushButton::hover {
            background-color: lightgreen;
        }
        """)
        button_save_keys.clicked.connect(self.save_key_to_json)

        label_input = QLabel("Input:", self.frame_encryption)
        label_input.setGeometry(10, 110, 120, 40)
        label_input.setStyleSheet("font-weight: bold; font-size: 20px;")

        self.text_input = QTextEdit(self.frame_encryption)
        self.text_input.setStyleSheet("background-color: white; font-size: 18px; font-weight: bold; border-radius: 10px; border: 2px solid blue;")
        self.text_input.setGeometry(10, 150, 760, 240)

        label_output = QLabel("Output:", self.frame_encryption)
        label_output.setGeometry(10, 400, 120, 40)
        label_output.setStyleSheet("font-weight: bold; font-size: 18px;")

        self.text_output = QTextEdit(self.frame_encryption)
        self.text_output.setStyleSheet("background-color: white; font-size: 18px; font-weight: bold; border-radius: 10px ; border: 2px solid blue;")
        self.text_output.setGeometry(10, 440, 760, 240)
        self.text_output.setReadOnly(True)

        button_encrypt = QPushButton("Encrypt", self.frame_encryption)
        button_encrypt.setGeometry(790, 360, 160, 40)
        button_encrypt.setCursor(Qt.PointingHandCursor)
        button_encrypt.clicked.connect(self.encrypt_message_handler)
        button_encrypt.setStyleSheet("""
        background-color: #68FF6A;
        font-weight: bold;
        font-size: 20px;
        border: 2px solid black;
        border-radius: 15px;
        QPushButton::hover {
            background-color: lightgreen;
        }
        """)

        button_decrypt = QPushButton("Decrypt", self.frame_encryption)
        button_decrypt.setGeometry(790, 430, 160, 40)
        button_decrypt.setCursor(Qt.PointingHandCursor)
        button_decrypt.clicked.connect(self.decrypt_message_handler)
        button_decrypt.setStyleSheet("""
        background-color: #68FF6A;
        font-weight: bold;
        font-size: 20px;
        border: 2px solid black;
        border-radius: 15px;
        QPushButton::hover {
            background-color: lightgreen;
        }
        """)

        # Compression Widgets
        self.frame_compression = QFrame(self.frame)
        self.frame_compression.setGeometry(10, 80, 980, 710)
        self.frame_compression.hide()

        label_input_file = QLabel("Input File:", self.frame_compression)
        label_input_file.setGeometry(10, 10, 120, 40)
        label_input_file.setStyleSheet("font-weight: bold; font-size: 18px;")

        self.entry_input_file = QLineEdit(self.frame_compression)
        self.entry_input_file.setStyleSheet("background-color: white; border-radius: 8px ; border: 2px solid blue;")
        self.entry_input_file.setGeometry(10, 60, 460, 40)

        button_select_file = QPushButton("Select", self.frame_compression)
        button_select_file.setGeometry(490, 60, 160, 40)
        button_select_file.setCursor(Qt.PointingHandCursor)
        button_select_file.clicked.connect(self.select_input_file)
        button_select_file.setStyleSheet("""
        background-color: #68FF6A;
        font-weight: bold;
        font-size: 20px;
        border: 2px solid black;
        border-radius: 15px;
        QPushButton::hover {
            background-color: lightgreen;
        }
        """)

        button_compress = QPushButton("Compress", self.frame_compression)
        button_compress.setGeometry(10, 110, 160, 40)
        button_compress.setCursor(Qt.PointingHandCursor)
        button_compress.setStyleSheet("""
        QPushButton {
            background-color: #d48d3b;
            font-weight: bold;
        font-weight: bold;
        font-size: 20px;
        border: 2px solid black;
        border-radius: 15px;
        }
        QPushButton:hover {
        
        font-weight: bold;
        font-size: 20px;
        border: 2px solid black;
        border-radius: 15px;
        background-color: #68FF6A;
        }
        QPushButton:checked {
        font-weight: bold;
        font-size: 20px;
        border: 2px solid black;
        border-radius: 15px;
        
        background-color: green;
    }
        """)
         

        button_compress.clicked.connect(self.compress_file)

        # Decompression Widgets
        self.frame_decompression = QFrame(self.frame)
        self.frame_decompression.setGeometry(10, 80, 980, 710)
        self.frame_decompression.hide()

        label_input_file = QLabel("Input File:", self.frame_decompression)
        label_input_file.setGeometry(10, 10, 120, 40)
        label_input_file.setStyleSheet("font-weight: bold; font-size: 18px;")

        self.entry_input_file = QLineEdit(self.frame_decompression)
        self.entry_input_file.setStyleSheet("background-color: white;border-radius: 8px; border: 2px solid blue;")
        self.entry_input_file.setGeometry(10, 60, 460, 40)

        button_select_file = QPushButton("Select", self.frame_decompression)
        button_select_file.setGeometry(490, 60, 160, 40)
        button_select_file.setCursor(Qt.PointingHandCursor)
        button_select_file.setStyleSheet("""
        background-color: #68FF6A;
        font-weight: bold;
        font-size: 20px;
        border: 2px solid black;
        border-radius: 15px;
        QPushButton::hover {
            background-color: lightgreen;
        }
        """)
        button_select_file.clicked.connect(self.select_input_file)

        button_decompress = QPushButton("Decompress", self.frame_decompression)
        button_decompress.setGeometry(10, 110, 160, 40)
        button_decompress.setCursor(Qt.PointingHandCursor)
        button_decompress.setStyleSheet("""
        QPushButton {
            background-color:#d48d3b ;
            font-weight: bold;
        font-weight: bold;
        font-size: 20px;
        border: 2px solid black;
        border-radius: 15px;
        }
        QPushButton:hover {
        
        font-weight: bold;
        font-size: 20px;
        border: 2px solid black;
        border-radius: 15px;
        background-color: #68FF6A;
        }
        QPushButton:checked {
        font-weight: bold;
        font-size: 20px;
        border: 2px solid black;
        border-radius: 15px;
        
        background-color: green;
    }
        """)
        button_decompress.clicked.connect(self.decompress_file)


    def show_encryption(self):
        self.frame_encryption.show()
        self.frame_compression.hide()
        self.frame_decompression.hide()

        self.button_encryption.setEnabled(False)
        self.button_compression.setEnabled(True)
        self.button_decompression.setEnabled(True)

    def show_compression(self):
        self.frame_encryption.hide()
        self.frame_compression.show()
        self.frame_decompression.hide()

        self.button_encryption.setEnabled(True)
        self.button_compression.setEnabled(False)
        self.button_decompression.setEnabled(True)

    def show_decompression(self):
        self.frame_encryption.hide()
        self.frame_compression.hide()
        self.frame_decompression.show()

        self.button_encryption.setEnabled(True)
        self.button_compression.setEnabled(True)
        self.button_decompression.setEnabled(False)

    def select_input_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select Input File")
        if filename:
            self.entry_input_file.setText(filename)

    def compress_file(self):
        input_file = self.entry_input_file.text().strip()
        if input_file:
            output_file, _ = QFileDialog.getSaveFileName(self, "Save Compressed File", "", "*.compressed")
            if output_file:
                try:
                    with open(input_file, 'rb') as file:
                        data = file.read()
                        compressed_data = zlib.compress(data, level=zlib.Z_BEST_COMPRESSION)
                    with open(output_file, 'wb') as file:
                        file.write(compressed_data)
                    QMessageBox.information(self, "Compression", "File compressed successfully!")
                except IOError:
                    QMessageBox.warning(self, "Compression Error", "Failed to compress the file.")

    def decompress_file(self):
        input_file = self.entry_input_file.text().strip()
        if input_file:
            output_file, _ = QFileDialog.getSaveFileName(self, "Save Decompressed File", "", "*.decompressed")
            if output_file:
                try:
                    with open(input_file, 'rb') as file:
                        compressed_data = file.read()
                        decompressed_data = zlib.decompress(compressed_data)
                    with open(output_file, 'wb') as file:
                        file.write(decompressed_data)
                    QMessageBox.information(self, "Decompression", "File decompressed successfully!")
                except IOError:
                    QMessageBox.warning(self, "Decompression Error", "Failed to decompress the file.")

    def generate_rsa_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        return private_key, public_key

    def encrypt_message_handler(self):
        plaintext = self.text_input.toPlainText()
        encrypted_message = self.encrypt_message(plaintext.encode('utf-8'), self.public_key_rsa)
        self.text_output.setPlainText(encrypted_message)

    def decrypt_message_handler(self):
        encrypted_message = self.text_input.toPlainText()
        decrypted_message = self.decrypt_message(encrypted_message, self.private_key_rsa)
        self.text_output.setPlainText(decrypted_message.decode('utf-8'))

    def encrypt_message(self, plaintext, public_key):
        encrypted_message = public_key.encrypt(
            plaintext,
            OAEP(
                mgf=MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_message.hex()

    def decrypt_message(self, encrypted_message, private_key):
        decrypted_message = private_key.decrypt(
            bytes.fromhex(encrypted_message),
            OAEP(
                mgf=MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message

    def save_key_to_json(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save RSA Key Pair", "", "*.json")
        if filename:
            data = {
                'private_key': self.private_key_rsa.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8'),
                'public_key': self.public_key_rsa.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
            }
            with open(filename, 'w') as file:
                json.dump(data, file)
            QMessageBox.information(self, "Save Keys", "RSA key pair saved successfully!")


if __name__ == "__main__":
    app = QApplication([])
    window = EncryptionCompressionTool()
    window.show()
    app.exec_()
