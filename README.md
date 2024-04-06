# File Encryption/Decryption GUI

This project is a simple graphical user interface (GUI) application designed for file encryption and decryption using the Fernet symmetric encryption scheme. It provides an easy-to-use interface for users to encrypt their files with a password and decrypt them later using the same password.

## Explanation

The provided Python code utilizes the PySimpleGUI library for building the GUI and the cryptography library for encryption and decryption operations. Here's how the code works:

1. **Imports**: The necessary libraries, including PySimpleGUI, cryptography, and base64, are imported.

```python
import PySimpleGUI as sg
import cryptography
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
```

2. **GUI Layout**: A GUI layout is defined using PySimpleGUI, including fields for selecting a file, entering a password, choosing between encryption or decryption, and buttons for OK and Cancel.

```python
layout = [
    [sg.Text("Select a file to encrypt or decrypt:")],
    [sg.Input(key="-FILEPATH-"), sg.FileBrowse()],
    [sg.Text("Enter a password:")],
    [sg.Input(key="-PASSWORD-", password_char="*")],
    [sg.Radio("Encrypt", "RADIO1", default=True, key="-ENCRYPT-"),
     sg.Radio("Decrypt", "RADIO1", key="-DECRYPT-")],
    [sg.Button("OK"), sg.Button("Cancel")]
]
```

3. **Window Creation**: A PySimpleGUI window is created with the defined layout.

```python
window = sg.Window("File Encryption/Decryption", layout)
```

4. **Event Loop**: The program enters a loop where it waits for events from the GUI, such as button clicks or window closure.

```python
while True:
    event, values = window.read()
    if event == sg.WINDOW_CLOSED or event == "Cancel":
        break
```

5. **Handling User Actions**: When the user clicks "OK" and enters a file path and password, the program checks if both are provided. If not, it prompts the user to enter both.

```python
    filepath = values["-FILEPATH-"]
    password = values["-PASSWORD-"]
    if not filepath or not password:
        sg.popup("Please enter a file and password")
        continue
```

6. **Mode Determination**: The program determines whether the user selected encryption or decryption mode based on the radio buttons.

```python
    mode = None
    if values["-ENCRYPT-"]:
        mode = "encrypt"
    elif values["-DECRYPT-"]:
        mode = "decrypt"
```

7. **Key Generation**: The password is encoded and used to generate a key using the PBKDF2HMAC key derivation function.

```python
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
```

8. **Encryption/Decryption**: A Fernet cipher object is initialized with the generated key. The content of the selected file is read in binary mode. If in encryption mode, the file content is encrypted using Fernet encryption and saved to a new file with ".encrypted" appended to the original filename. If in decryption mode, the encrypted data is decrypted using the Fernet cipher object. If decryption fails (possibly due to an incorrect password), an error message is displayed. If successful, the decrypted data is saved to a new file with the ".encrypted" extension removed.

```python
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
```

9. **Window Closure**: The PySimpleGUI window is closed when the loop ends.

```python
window.close()
```

This project provides a user-friendly way to encrypt and decrypt files, enhancing data security and privacy for users.
