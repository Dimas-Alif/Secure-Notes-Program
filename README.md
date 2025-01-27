# Aplikasi Secure Notes

Aplikasi ini fokus pada keamanan untuk menyimpan catatan terenkripsi, dengan berbagai lapisan perlindungan terhadap akses yang tidak sah dan ancaman terhadap sistem. Aplikasi ini menggunakan enkripsi AES untuk penyimpanan catatan dan dilengkapi dengan mekanisme perlindungan tambahan seperti deteksi tangkapan layar, deteksi perangkat mencurigakan melalui webcam, serta login dengan hashing dan salting password.

## Fitur

- **Enkripsi & Dekripsi AES**: Menggunakan AES (Advanced Encryption Standard) dengan mode CBC untuk mengenkripsi dan mendekripsi catatan.
- **Deteksi Tangkapan Layar**: Mendeteksi percobaan tekan tombol PrintScreen dan menghancurkan semua catatan serta program jika tangkapan layar terdeteksi.
- **Deteksi Perangkat Mencurigakan**: Memantau webcam untuk mendeteksi wajah ganda (menunjukkan perangkat mencurigakan) dan menghancurkan catatan jika terdeteksi.
- **Login Password**: Memerlukan password untuk mengakses catatan terenkripsi dengan hashing dan salting password yang aman (bcrypt).
- **Perlindungan Percobaan Login Gagal**: Membatasi jumlah percobaan login yang gagal, dan merusak sistem jika jumlah percobaan melebihi batas.
- **UI Kalkulator Palsu**: Antarmuka kalkulator palsu yang memerlukan login untuk mengakses fungsionalitas penuh.
- **Obfuscation (Pengaburan)**: Kode diobfuscate untuk menyulitkan pemahaman logika program oleh pengguna yang tidak sah.
- **Penghancuran Sistem**: Jika ancaman terdeteksi atau terlalu banyak percobaan login gagal, program akan menghancurkan catatan dan dirinya sendiri.
- **Manajemen Catatan Terenkripsi**: Memungkinkan penyimpanan dan pembacaan catatan terenkripsi dengan cara yang aman.

## Persyaratan

- Python 3.x
- OpenCV (untuk deteksi webcam)
- Cryptography (untuk enkripsi AES)
- Tkinter (untuk GUI)
- Bcrypt (untuk hashing password)

## Instalasi

1. Clone repository:
    ```bash
    git clone https://github.com/Dimas-Alif/Secure-Notes-Program.git
    cd Secure-Notes-Program
    ```

2. Instal dependensi yang dibutuhkan:
    ```bash
    pip install opencv-python cryptography bcrypt
    ```

3. Pastikan webcam Anda berfungsi jika menggunakan fitur deteksi perangkat mencurigakan.

## Penggunaan

### Menjalankan Aplikasi

Untuk menjalankan aplikasi, eksekusi file Python:
```bash
python secure_notes.py
