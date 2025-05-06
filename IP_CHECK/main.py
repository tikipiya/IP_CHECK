import nmap
import socket
import re
import os
import requests
import json
import threading
from urllib.parse import urlparse
from datetime import datetime
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from colorama import init, Fore, Style
import tkinter as tk
from tkinter import scrolledtext

# カラー出力の初期化
init(autoreset=True)

# ログウィンドウのクラス
class LogWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("スキャンログ")
        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=100, height=30)
        self.text_area.pack(padx=10, pady=10)
        self.text_area.configure(state='disabled')

    def log(self, message):
        self.text_area.configure(state='normal')
        self.text_area.insert(tk.END, message + '\n')
        self.text_area.see(tk.END)
        self.text_area.configure(state='disabled')

    def start(self):
        self.root.mainloop()

# 脆弱性チェック関数
def analyze_service(port, service):
    if port == 22 and service == "ssh":
        return "SSHが開いています：パスワード認証の脆弱性に注意"
    elif port == 80 and service == "http":
        return "HTTPが開いています：HTTPSを使用することを検討"
    elif port == 443 and service == "https":
        return "HTTPSが開いています：証明書の有効性を確認してください"
    elif port == 3306:
        return "MySQLが開いています：外部アクセスを制限してください"
    elif port == 23:
        return "Telnetが開いています：非常に危険！使用非推奨"
    else:
        return "特に重大なリスクは検出されませんでした"

# PDF出力関数
def generate_pdf_report(results, host, ip, filename="vuln_report.pdf"):
    c = canvas.Canvas(filename)
    pdfmetrics.registerFont(UnicodeCIDFont('HeiseiKakuGo-W5'))
    c.setFont("HeiseiKakuGo-W5", 12)
    c.drawString(100, 800, "脆弱性スキャンレポート")
    c.drawString(100, 785, f"対象ホスト: {host}")
    c.drawString(100, 770, f"対象IP: {ip}")
    c.drawString(100, 755, f"日時: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    y = 730
    for result in results:
        text = f"ポート {result['port']} ({result['service']}) - {result['analysis']}"
        c.drawString(100, y, text)
        y -= 20
        if 'cve_info' in result and result['cve_info']:
            for cve in result['cve_info']:
                c.drawString(120, y, f"CVE-ID: {cve['id']}")
                y -= 20
                c.drawString(140, y, f"説明: {cve['description']}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = 800
        if y < 50:
            c.showPage()
            y = 800

    c.save()

# ホスト名またはIPの解析
def parse_target(input_str):
    # URLからホスト名を抽出
    if input_str.startswith("http://") or input_str.startswith("https://"):
        parsed_url = urlparse(input_str)
        host = parsed_url.hostname
    else:
        host = input_str

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return None, None

    return host, ip

# CVE情報の取得関数
def get_cve_info(service_name, version):
    cve_list = []
    try:
        # NVDのAPIを使用してCVE情報を取得
        base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
        params = {
            'keyword': f"{service_name} {version}",
            'resultsPerPage': 5
        }
        response = requests.get(base_url, params=params)
        if response.status_code == 200:
            data = response.json()
            for item in data.get('result', {}).get('CVE_Items', []):
                cve_id = item['cve']['CVE_data_meta']['ID']
                description = item['cve']['description']['description_data'][0]['value']
                cve_list.append({'id': cve_id, 'description': description})
    except Exception as e:
        pass
    return cve_list

# メイン処理
def run_scan(log_window):
    target_input = input("スキャン対象のホスト名またはIPアドレスを入力してください: ").strip()
    host, ip = parse_target(target_input)
    if not ip:
        log_window.log("[!] 無効なホスト名またはIPアドレスです。")
        return

    log_window.log(f"[*] スキャン対象: {host} ({ip})")
    log_window.log("[*] 【開始】IPアドレススキャンを開始します...")

    nm = nmap.PortScanner()
    try:
        # サービス検出とスクリプトスキャンを実行
        nm.scan(ip, arguments='-sV --script=default')
    except Exception as e:
        log_window.log(f"[!] スキャン中にエラーが発生しました: {e}")
        return

    log_window.log("[*] 【完了】IPアドレススキャンが完了しました。")

    results = []

    for proto in nm[ip].all_protocols():
        ports = nm[ip][proto].keys()
        for port in sorted(ports):
            log_window.log(f"[*] 【開始】ポート {port} のスキャンを開始します...")
            service = nm[ip][proto][port]['name']
            version = nm[ip][proto][port].get('version', '')
            analysis = analyze_service(port, service)

            log_window.log(f"[*] 【開始】ポート {port} のCVE情報取得を開始します...")
            cve_info = get_cve_info(service, version)
            log_window.log(f"[*] 【完了】ポート {port} のCVE情報取得が完了しました。")

            results.append({
                "port": port,
                "service": service,
                "analysis": analysis,
                "cve_info": cve_info
            })

            log_window.log(f"[+] {port}/tcp ({service}): {analysis}")
            if cve_info:
                for cve in cve_info:
                    log_window.log(f"    [-] CVE-ID: {cve['id']}")
                    log_window.log(f"        説明: {cve['description']}")
            log_window.log(f"[*] 【完了】ポート {port} のスキャンが完了しました。")

    generate_pdf_report(results, host, ip)
    log_window.log(f"[+] レポートを出力しました: vuln_report.pdf")

# 実行
if __name__ == "__main__":
    log_win = LogWindow()
    scan_thread = threading.Thread(target=run_scan, args=(log_win,))
    scan_thread.start()
    log_win.start()