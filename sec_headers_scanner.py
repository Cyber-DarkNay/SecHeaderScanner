#!/usr/bin/env python3
"""
Web Security Header & Misconfiguration Scanner
Author: Cyber DarkNay
Scan header keamanan, SSL, CSP, cookie, dan beri skor.
Usage: python sec_headers_scanner.py
"""

import requests
import ssl
import socket
import sys
import json
from datetime import datetime
from urllib.parse import urlparse

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box
    from rich.text import Text
    console = Console()
except ImportError:
    console = None
    print("Install rich untuk tampilan lebih baik: pip install rich")

# ======================
# KONFIGURASI
# ======================
TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Daftar header keamanan yang penting
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS - memaksa HTTPS",
    "Content-Security-Policy": "CSP - mencegah XSS & injection",
    "X-Frame-Options": "Mencegah clickjacking (DENY/SAMEORIGIN)",
    "X-Content-Type-Options": "Mencegah MIME sniffing (nosniff)",
    "Referrer-Policy": "Mengontrol informasi referer",
    "Permissions-Policy": "Membatasi akses fitur browser",
    "X-XSS-Protection": "Perlindungan XSS lama (tidak direkomendasikan modern)",
    "Cross-Origin-Embedder-Policy": "COEP - isolasi cross-origin",
    "Cross-Origin-Opener-Policy": "COOP - isolasi window",
    "Cross-Origin-Resource-Policy": "CORP - kontrol resource",
}

# Skor untuk setiap header (bobot)
HEADER_SCORES = {
    "Strict-Transport-Security": 20,
    "Content-Security-Policy": 30,
    "X-Frame-Options": 10,
    "X-Content-Type-Options": 10,
    "Referrer-Policy": 5,
    "Permissions-Policy": 5,
    "Cross-Origin-Embedder-Policy": 5,
    "Cross-Origin-Opener-Policy": 5,
    "Cross-Origin-Resource-Policy": 5,
}

# ======================
# FUNGSI SCANNER
# ======================
def check_ssl(domain, port=443):
    """Ambil info SSL certificate"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "valid": True,
                    "expiry": cert.get("notAfter"),
                    "issuer": dict(cert.get("issuer", []))[0][0][1] if cert.get("issuer") else "Unknown",
                    "subject": dict(cert.get("subject", []))[0][0][1] if cert.get("subject") else "Unknown",
                    "version": ssock.version(),
                    "cipher": ssock.cipher()[0] if ssock.cipher() else "-"
                }
    except Exception as e:
        return {"valid": False, "error": str(e)}

def check_headers(url):
    """Ambil response headers dari URL"""
    try:
        r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT}, allow_redirects=True)
        return r.headers, r.status_code, r.history
    except Exception as e:
        return None, None, None

def analyze_cookie(cookie_header):
    """Analisa keamanan cookie (HttpOnly, Secure, SameSite)"""
    cookies = []
    # cookie_header bisa string seperti "sessionid=abc; HttpOnly; Secure"
    parts = cookie_header.split(';')
    for part in parts:
        if '=' in part and not part.strip().startswith('HttpOnly') and not part.strip().startswith('Secure'):
            cookies.append(part.strip())
    # Sekarang cek atribut keamanan pada seluruh header
    flags = {
        "HttpOnly": "HttpOnly" in cookie_header,
        "Secure": "Secure" in cookie_header,
        "SameSite": "SameSite" in cookie_header,
    }
    return {
        "cookies_found": cookies,
        "secure_flags": flags
    }

def score_security(headers):
    """Beri skor berdasarkan header keamanan yang ada"""
    score = 0
    details = {}
    for header, desc in SECURITY_HEADERS.items():
        value = headers.get(header)
        if value:
            # Beri skor sesuai bobot
            points = HEADER_SCORES.get(header, 5)
            score += points
            details[header] = {"status": "✅", "value": value[:80], "points": points}
        else:
            points = HEADER_SCORES.get(header, 5)
            details[header] = {"status": "❌", "value": None, "points": 0}
    return score, details

def grade_score(score):
    """Konversi skor ke grade A-F"""
    if score >= 80:
        return "A", "green"
    elif score >= 60:
        return "B", "cyan"
    elif score >= 40:
        return "C", "yellow"
    elif score >= 20:
        return "D", "orange"
    else:
        return "F", "red"

def scan_website(url):
    """Main scanning function"""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    if ':' in domain:
        domain = domain.split(':')[0]
    
    results = {
        "url": url,
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "final_url": None,
        "status_code": None,
        "redirects": [],
        "ssl": None,
        "headers": None,
        "security_score": None,
        "grade": None,
        "header_details": {},
        "cookie_security": {},
        "vulnerability_notes": []
    }
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=False) as progress:
        task = progress.add_task("[cyan]Memindai...", total=3)
        
        progress.update(task, description="[cyan]🔒 Memeriksa SSL...")
        results["ssl"] = check_ssl(domain)
        progress.advance(task)
        
        progress.update(task, description="[cyan]🌐 Mengambil header HTTP...")
        headers, status, redirects = check_headers(url)
        if headers:
            results["headers"] = dict(headers)
            results["status_code"] = status
            results["final_url"] = redirects[-1].url if redirects else url
            results["redirects"] = [r.url for r in redirects]
            # Analisa cookie
            set_cookie = headers.get("Set-Cookie")
            if set_cookie:
                results["cookie_security"] = analyze_cookie(set_cookie)
            # Skor keamanan
            score, details = score_security(headers)
            results["security_score"] = score
            results["grade"], grade_color = grade_score(score)
            results["header_details"] = details
            # Catatan kelemahan
            notes = []
            if not headers.get("Strict-Transport-Security"):
                notes.append("HSTS tidak diaktifkan - rentan terhadap downgrade attack")
            if not headers.get("Content-Security-Policy"):
                notes.append("CSP tidak ditemukan - rentan terhadap XSS dan injection")
            if not headers.get("X-Frame-Options"):
                notes.append("X-Frame-Options tidak ada - potensi clickjacking")
            if set_cookie and "Secure" not in set_cookie:
                notes.append("Cookie tanpa flag Secure - dapat dikirim via HTTP")
            if set_cookie and "HttpOnly" not in set_cookie:
                notes.append("Cookie tanpa flag HttpOnly - dapat diakses oleh JavaScript (XSS)")
            if headers.get("Server"):
                server = headers.get("Server")
                if any(x in server.lower() for x in ["apache", "nginx", "iis"]):
                    notes.append(f"Server version terdeteksi: {server} - informatif bagi attacker")
            results["vulnerability_notes"] = notes
        else:
            results["error"] = "Tidak dapat terhubung"
        progress.advance(task)
        
        progress.update(task, description="[cyan]✅ Selesai")
        progress.advance(task)
    
    return results

# ======================
# OUTPUT RICH
# ======================
def display_results(results):
    if not console:
        print(json.dumps(results, indent=2))
        return
    
    console.clear()
    grade_color = "green" if results["grade"] == "A" else "cyan" if results["grade"] == "B" else "yellow" if results["grade"] == "C" else "red"
    console.print(Panel.fit(
        f"[bold cyan]🛡️ WEB SECURITY HEADER SCANNER[/bold cyan]\n[white]Hasil untuk {results['url']}[/white]\n[bold {grade_color}]Grade: {results['grade']} (Skor: {results['security_score']}/100)[/bold {grade_color}]",
        border_style="cyan"
    ))
    
    # Ringkasan
    table_summary = Table(title="📋 RINGKASAN", style="cyan", box=box.ROUNDED)
    table_summary.add_column("Item")
    table_summary.add_column("Nilai")
    table_summary.add_row("Status Code", str(results.get("status_code", "-")))
    table_summary.add_row("Final URL", results.get("final_url", "-"))
    table_summary.add_row("Redirects", str(len(results.get("redirects", []))))
    table_summary.add_row("SSL Valid", "✅" if results.get("ssl", {}).get("valid") else "❌")
    if results.get("ssl", {}).get("expiry"):
        table_summary.add_row("SSL Expiry", results["ssl"]["expiry"])
    table_summary.add_row("Cipher", results.get("ssl", {}).get("cipher", "-"))
    console.print(table_summary)
    
    # Header keamanan
    header_table = Table(title="🔐 SECURITY HEADERS", style="cyan", box=box.SIMPLE)
    header_table.add_column("Header", style="bold")
    header_table.add_column("Status")
    header_table.add_column("Value / Catatan")
    for header, info in results["header_details"].items():
        status_icon = info["status"]
        value = info["value"] if info["value"] else "-"
        header_table.add_row(header, status_icon, value[:60])
    console.print(header_table)
    
    # Cookie security
    if results.get("cookie_security"):
        cookie_data = results["cookie_security"]
        cookie_table = Table(title="🍪 COOKIE SECURITY", box=box.SIMPLE)
        cookie_table.add_column("Atribut")
        cookie_table.add_column("Status")
        for flag, present in cookie_data["secure_flags"].items():
            cookie_table.add_row(flag, "✅" if present else "❌")
        if cookie_data["cookies_found"]:
            cookie_table.add_row("Nama Cookie", ", ".join(cookie_data["cookies_found"][:3]))
        console.print(cookie_table)
    
    # Catatan kelemahan
    if results.get("vulnerability_notes"):
        notes = "\n".join([f"⚠️ {note}" for note in results["vulnerability_notes"]])
        console.print(Panel(notes, title="⚠️ KELEMAHAN TERDETEKSI", border_style="red"))
    else:
        console.print(Panel("[green]✅ Tidak ditemukan kelemahan signifikan[/green]", title="✅ KESIMPULAN", border_style="green"))
    
    # Rekomendasi perbaikan
    recos = []
    if not results["header_details"]["Strict-Transport-Security"]["status"] == "✅":
        recos.append("Aktifkan HSTS: tambahkan header 'Strict-Transport-Security: max-age=31536000; includeSubDomains'")
    if not results["header_details"]["Content-Security-Policy"]["status"] == "✅":
        recos.append("Implementasikan CSP: gunakan 'Content-Security-Policy: default-src 'self'' terlebih dahulu")
    if not results["header_details"]["X-Frame-Options"]["status"] == "✅":
        recos.append("Cegah clickjacking: tambahkan 'X-Frame-Options: DENY'")
    if results.get("cookie_security", {}).get("secure_flags", {}).get("Secure") == False:
        recos.append("Cookie tanpa Secure: pastikan cookie hanya dikirim lewat HTTPS dengan flag Secure")
    if results.get("cookie_security", {}).get("secure_flags", {}).get("HttpOnly") == False:
        recos.append("Cookie tanpa HttpOnly: tambahkan flag HttpOnly untuk proteksi XSS")
    if recos:
        rec_text = "\n".join([f"🔧 {r}" for r in recos[:5]])
        console.print(Panel(rec_text, title="🛠️ REKOMENDASI PERBAIKAN", border_style="yellow"))

def main():
    if not console:
        print("=" * 50)
        print("WEB SECURITY HEADER SCANNER")
        print("Author: Cyber DarkNay")
        print("=" * 50)
    
    target = input("\n[?] Masukkan URL (contoh: https://example.com atau example.com): ").strip()
    if not target:
        print("URL tidak boleh kosong.")
        sys.exit(1)
    
    results = scan_website(target)
    
    if console:
        display_results(results)
    else:
        print(json.dumps(results, indent=2))
    
    # Simpan ke JSON
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"sec_report_{results['domain']}_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(results, f, indent=2, default=str)
    if console:
        console.print(f"\n[bold green]📁 Laporan disimpan ke {filename}[/bold green]")
    else:
        print(f"\nLaporan disimpan ke {filename}")

if __name__ == "__main__":
    main()
