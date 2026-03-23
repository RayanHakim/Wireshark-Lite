📡 Wireshark Lite: Network Packet Sniffer Pro
Wireshark Lite adalah aplikasi pemantau jaringan (Network Monitoring) berbasis Python yang dirancang untuk menangkap, membedah, dan menganalisis paket data secara real-time. Proyek ini mendemonstrasikan implementasi Raw Sockets, Multithreading, dan Deep Packet Inspection (DPI) dalam lingkungan simulasi keamanan.

1. Cara Cek Status (Apakah "Pintu" Terbuka?)
Sebelum mengubah apa pun, sebaiknya cek dulu status koneksi Wi-Fi kamu saat ini.

Klik Start, ketik PowerShell.

Klik kanan pada PowerShell, lalu pilih Run as Administrator (Wajib!).

Ketik perintah ini dan tekan Enter:

PowerShell
Get-NetIPInterface | select InterfaceAlias, Forwarding
Cara Baca Hasilnya:

Cari baris yang namanya Wi-Fi.

Jika Disabled: Pintu tertutup (HP orang tua bakal Offline kalau kamu monitor).

Jika Enabled: Pintu terbuka (Internet akan lancar lewat laptopmu).

2. Cara Aktivasi (Buka "Pintu" Jaringan)
Gunakan ini HANYA saat kamu ingin menjalankan aplikasi Wireshark Lite untuk memantau perangkat lain.

Di jendela PowerShell yang sama (Admin), ketik:

PowerShell
Set-NetIPInterface -Forwarding Enabled
Tekan Enter. (Biasanya tidak muncul tulisan apa-apa jika berhasil).

Verifikasi: Ulangi langkah nomor 1 di atas untuk memastikan status Wi-Fi sudah berubah jadi Enabled.

3. Cara Non-Aktivasi (Tutup "Pintu" Demi Keamanan)
Sangat disarankan melakukan ini setelah kamu selesai menggunakan program, agar laptopmu tidak bisa dimanfaatkan orang asing di jaringan lain.

Di jendela PowerShell (Admin), ketik:

PowerShell
Set-NetIPInterface -Forwarding Disabled
Tekan Enter.

Verifikasi: Cek lagi dengan perintah Get-NetIPInterface tadi. Pastikan Wi-Fi kembali ke status Disabled.

💡 Tips Tambahan: Kenapa Harus "Run as Administrator"?
Jika kamu lupa menjalankan PowerShell sebagai Admin, perintah Set-NetIPInterface akan ditolak dengan pesan "Access Denied". Ini adalah fitur keamanan Windows agar tidak sembarang aplikasi bisa mengubah jalur internet kamu.

✨ Fitur Unggulan
🚀 Real-time Sniffing: Menangkap paket IP, TCP, UDP, dan ICMP yang melintas di Network Interface Card (NIC).

🔍 Deep Packet Inspection: Fitur Double-click pada baris tabel untuk membuka jendela detail yang membedah seluruh lapisan protokol (Layer 2 - Layer 7).

🔢 Hex & Raw Viewer: Representasi data mentah dalam bentuk Heksadesimal untuk analisis forensik digital dan pencarian payload.

⚡ Protocol Filtering: Menyaring lalu lintas data berdasarkan protokol spesifik (TCP, UDP, ICMP) agar analisis lebih fokus.

🌐 Simple Whois (Reverse DNS): Identifikasi otomatis nama host tujuan untuk mengetahui pemilik IP (seperti Google, Microsoft, atau GitHub).

🧹 Clean UI & UX: Antarmuka bersih dengan fitur Clear Screen, Auto-scroll, dan indikator status yang informatif.

🛠️ Tech Stack
Language: Python 3.x

Core Engine: Scapy (Library manipulasi paket tingkat lanjut).

GUI Framework: Tkinter (Native Python GUI).

Logic: Socket Programming, Threading, & Networking Protocols.

📂 Struktur Proyek
Plaintext
/Wireshark-Lite
  ├── main.py          <-- Titik masuk aplikasi (GUI & Controller)
  ├── sniffer_core.py  <-- Mesin pemroses paket (Backend Logic)
  ├── screenshot.jpg   <-- Dokumentasi tampilan aplikasi
  └── README.md        <-- Dokumentasi proyek
🚀 Cara Instalasi & Menjalankan
1. Prasyarat
Pastikan Python sudah terinstal di sistem Anda. Instal library Scapy melalui terminal/command prompt:

Bash
pip install scapy
2. Hak Akses (PENTING)
Karena aplikasi ini mengakses Raw Sockets di level Kernel sistem operasi, Anda WAJIB menjalankannya dengan hak akses administrator agar kartu jaringan bisa masuk ke Promiscuous Mode:

Windows: Buka terminal/VS Code sebagai Administrator, lalu jalankan:

PowerShell
python main.py
Linux/macOS: Gunakan perintah sudo:

Bash
sudo python3 main.py
📸 Tampilan Aplikasi
(Catatan: Pastikan file screenshot kamu bernama screenshot.jpg agar muncul di GitHub)

⚠️ Pernyataan Etika (Disclaimer)
Proyek ini dibuat murni untuk tujuan Edukasi dan Keamanan Jaringan. Penggunaan alat ini untuk memantau jaringan tanpa izin pemiliknya adalah tindakan ilegal. Selalu gunakan alat ini secara bijak di lingkungan laboratorium pribadi Anda sendiri.
