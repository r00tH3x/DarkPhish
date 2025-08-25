# 🕵️ DarkPhish v2 — *Cybersecurity Educational Toolkit*

⚠️ **Disclaimer Penting**  
DarkPhish dibuat **hanya untuk tujuan edukasi & penelitian** dalam **lingkungan lab yang terisolasi**.  
🚫 Jangan pernah menggunakan tool ini pada jaringan atau sistem tanpa **izin eksplisit**, karena itu ilegal & berbahaya.  
✅ Cocok dipakai buat **belajar, simulasi serangan, dan riset keamanan siber**.  

---

## ✨ Fitur Utama
- 🔍 **Network Scanner** → deteksi perangkat aktif di jaringan (via ARP)  
- 🎭 **ARP & DNS Spoofing Simulation** → memahami cara kerja serangan MITM (hanya untuk lab)  
- 📂 **Website Cloner** → menyimpan halaman HTML ke lokal untuk studi  
- 🌐 **Phishing Server (Simulasi)** → jalankan server lab untuk menangkap form data (tersimpan ke SQLite DB)  
- 📊 **Captured Data Viewer** → menampilkan data hasil simulasi dengan tabel rapih  

---

## 📦 Instalasi

### 1. Clone Repo
```bash
git clone https://github.com/username/darkphish.git
cd darkphish
```

### 2. Install Dependensi
Pastikan Python 3 sudah terpasang, lalu jalankan:
```bash
pip install scapy colorama netifaces requests tabulate
```

---

## 🛠️ Alur Penggunaan
Agar simulasi berjalan lancar di lab environment, ikuti alur berikut:

1. 🔍 **Scan Network**  
   - Jalankan menu **1. Pindai Jaringan** untuk mengetahui perangkat aktif.  
   - Catat IP target dan gateway.  

2. 📂 **Clone Website**  
   - Jalankan menu **3. Kloning Website** untuk mengunduh halaman login (contoh: `https://example.com`).  
   - File akan tersimpan di folder `cloned_website/`.

3. 🌐 **Jalankan Phishing Server**  
   - Gunakan menu **4. Jalankan Server Phishing**.  
   - Server lokal akan menyajikan halaman kloning, dan semua input form akan disimpan ke database `phishing_data.db`.  
   - ⚡ **Tips:** Jalankan server ini di **terminal terpisah**, agar tetap aktif ketika Anda lanjut ke tahap spoofing.  

4. 🎭 **DNS Spoofing Simulation**  
   - Pilih menu **2. Mulai Serangan DNS Spoofing**.  
   - Masukkan IP target, lalu atur domain yang ingin dialihkan (misalnya `facebook.com → 192.168.1.100`).  
   - Target yang membuka domain tersebut akan diarahkan ke server phishing Anda (yang sudah berjalan di terminal lain).  

5. 📊 **Lihat Data yang Ditangkap**  
   - Gunakan menu **5. Lihat Data yang Ditangkap** untuk menampilkan input form yang tersimpan di database.  
   - Data ditampilkan dalam tabel rapih di terminal.  

---

## 📂 Struktur Proyek
```
darkphish/
│── darkphish.py       # Main script
│── phishing_data.db   # Database SQLite (dibuat otomatis)
│── cloned_website/    # Folder hasil clone website
│── darkphish.log      # Log aktivitas
```

---

## 📚 Contoh Output (Lab Environment)

### 🔍 Network Scan
```
--- Perangkat Aktif di Jaringan ---
+---------------+-------------------+-----------------+
| IP Address    | MAC Address       | Vendor          |
+---------------+-------------------+-----------------+
| 192.168.1.10  | aa:bb:cc:dd:ee:ff | TP-LINK Tech    |
| 192.168.1.15  | 11:22:33:44:55:66 | Apple Inc.      |
+---------------+-------------------+-----------------+
```

### 📊 Captured Data Viewer
```
--- Data yang Berhasil Ditangkap ---
+----+-------------------------+---------------------+
| ID | Data Form               | Waktu               |
+----+-------------------------+---------------------+
| 1  | username: admin          | 2025-08-25 10:10:10 |
|    | password: 123456         |                     |
+----+-------------------------+---------------------+
```

---

## 📝 Catatan Etika
- ⚡ Jalankan hanya di **lingkungan lab** (misalnya jaringan virtual/VM).  
- 🔒 Jangan sekali-kali digunakan pada jaringan publik atau pihak ketiga.  
- 🎓 Tujuan utama → **pembelajaran, riset, dan simulasi berizin**.  

---

## 🎨 Tips Biar README Makin Keren
- Pasang **badge** (contoh: Python, License, dll)  
- Tambahin **screenshot terminal** (output scanning / viewer tabel)  
- Bikin **demo GIF** alur kerja (simulasi di lab)  

---

## 📜 Lisensi
Proyek ini dilisensikan di bawah [MIT License](LICENSE).  
Gunakan secara **etis, aman, dan legal**. 🚀

