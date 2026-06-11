<p align="center">
  <img src="https://img.shields.io/badge/Security-Scanner-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python"/>
  <img src="https://img.shields.io/badge/Author-Cyber%20DarkNay-blue?style=for-the-badge"/>
  <img src="https://img.shields.io/github/stars/Cyber-DarkNay/SecHeaderScanner?style=social"/>
</p>

# 🛡️ Web Security Header & Misconfiguration Scanner

> **Scan header keamanan, SSL, cookie, dan CSP – dapatkan skor dan rekomendasi perbaikan untuk website Anda.**

Tools ini memeriksa **10+ security headers** penting, mengecek SSL certificate, menganalisa keamanan cookie, dan memberikan **grade A-F** serta rekomendasi perbaikan. Cocok untuk developer, bug hunter, dan profesional keamanan.

---

## ⚡ Fitur

- ✅ Pemeriksaan **security headers** (HSTS, CSP, X-Frame-Options, dll)
- 🔒 Validasi **SSL/TLS** (expiry, cipher, issuer)
- 🍪 Analisis keamanan **cookie** (HttpOnly, Secure, SameSite)
- 📊 **Skor keamanan** 0-100 dan grade A-F
- ⚠️ Deteksi kelemahan umum (missing headers, cookie flags)
- 🛠️ Rekomendasi perbaikan spesifik
- 💾 Laporan JSON lengkap
- 🎨 Output cantik dengan tabel warna

---

## 🚀 Instalasi

```bash
git clone https://github.com/Cyber-DarkNay/SecHeaderScanner.git
cd SecHeaderScanner
pip install -r requirements.txt
