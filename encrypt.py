import PySimpleGUI as sg
import cryptography
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


layout = [
    [sg.Text("Select a file to encrypt or decrypt:")],
    [sg.Input(key="-FILEPATH-"), sg.FileBrowse()],
    [sg.Text("Enter a password:")],
    [sg.Input(key="-PASSWORD-", password_char="*")],
    [sg.Radio("Encrypt", "RADIO1", default=True, key="-ENCRYPT-"),
     sg.Radio("Decrypt", "RADIO1", key="-DECRYPT-")],
    [sg.Button("OK"), sg.Button("Cancel")]
]


window = sg.Window("File Encryption/Decryption", layout)


while True:
    event, values = window.read()
    if event == sg.WINDOW_CLOSED or event == "Cancel":
        break

    
    filepath = values["-FILEPATH-"]
    password = values["-PASSWORD-"]
    if not filepath or not password:
        sg.popup("Please enter a file and password")
        continue

    
    mode = None
    if values["-ENCRYPT-"]:
        mode = "encrypt"
    elif values["-DECRYPT-"]:
        mode = "decrypt"

    passw = password.encode()

    salt = "saltysalt".encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passw))
    f = Fernet(key)

    with open(filepath, "rb") as file:
        data = file.read()
        
    if mode == "encrypt":
        encrypted_data = f.encrypt(data)
        new_filename = f"{filepath}.encrypted"
        with open(new_filename, "wb") as file:
            file.write(encrypted_data)
        sg.popup(f"File encrypted and saved as {new_filename}")
    elif mode == "decrypt":
        try:
            decrypted_data = f.decrypt(encrypted_data.decode())
        except cryptography.fernet.InvalidToken:
            sg.popup("Invalid password or file")
            continue
        new_filename = filepath.rsplit(".", 1)[0] 
        with open(new_filename, "wb") as file:
            file.write(decrypted_data)
        sg.popup(f"File decrypted and saved as {new_filename}")
        

window.close()

