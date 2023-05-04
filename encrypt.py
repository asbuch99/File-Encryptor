import PySimpleGUI as sg
import cryptography
from cryptography.fernet import Fernet

# Define the GUI layout
layout = [
    [sg.Text("Select a file to encrypt or decrypt:")],
    [sg.Input(key="-FILEPATH-"), sg.FileBrowse()],
    [sg.Text("Enter a password:")],
    [sg.Input(key="-PASSWORD-", password_char="*")],
    [sg.Radio("Encrypt", "RADIO1", default=True, key="-ENCRYPT-"),
     sg.Radio("Decrypt", "RADIO1", key="-DECRYPT-")],
    [sg.Button("OK"), sg.Button("Cancel")]
]

# Create the GUI window
window = sg.Window("File Encryption/Decryption", layout)

# Loop to handle events
while True:
    event, values = window.read()
    if event == sg.WINDOW_CLOSED or event == "Cancel":
        break

    # Check that a file and password have been entered
    filepath = values["-FILEPATH-"]
    password = values["-PASSWORD-"]
    if not filepath or not password:
        sg.popup("Please enter a file and password")
        continue

    # Determine whether to encrypt or decrypt
    mode = None
    if values["-ENCRYPT-"]:
        mode = "encrypt"
    elif values["-DECRYPT-"]:
        mode = "decrypt"

    # Perform the encryption or decryption
    with open(filepath, "rb") as file:
        data = file.read()
    fernet = Fernet(bytes(password, "utf-8"))
    if mode == "encrypt":
        encrypted_data = fernet.encrypt(data)
        new_filename = f"{filepath}.encrypted"
        with open(new_filename, "wb") as file:
            file.write(encrypted_data)
        sg.popup(f"File encrypted and saved as {new_filename}")
    elif mode == "decrypt":
        try:
            decrypted_data = fernet.decrypt(data)
        except cryptography.fernet.InvalidToken:
            sg.popup("Invalid password or file")
            continue
        new_filename = filepath.rsplit(".", 1)[0] # remove the ".encrypted" extension
        with open(new_filename, "wb") as file:
            file.write(decrypted_data)
        sg.popup(f"File decrypted and saved as {new_filename}")

window.close()

