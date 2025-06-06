import tkinter as tk
from tkinter import messagebox, scrolledtext, DISABLED, NORMAL
import requests
import socket
import dns.resolver

# Function to scan website security
def scan_website():
    url = website_entry.get()
    try:
        response = requests.get(url)
        headers = response.headers
        security_headers = ['X-Frame-Options', 'X-XSS-Protection', 'Content-Security-Policy']
        missing_headers = [h for h in security_headers if h not in headers]
        
        result = f"[+] Status: {response.status_code}\n"
        if missing_headers:
            result += "[-] Missing Security Headers: " + ", ".join(missing_headers) + "\n"
        else:
            result += "[+] All Security Headers Present!\n"
        
        result_text.config(state=NORMAL)
        result_text.insert(tk.END, result + "\n")
        result_text.config(state=DISABLED)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to scan: {e}")

# Function to check open ports
def scan_ports():
    target = website_entry.get().replace("http://", "").replace("https://", "").split("/")[0]
    common_ports = [21, 22, 25, 80, 443, 3306]
    open_ports = []
    
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        if not sock.connect_ex((target, port)):
            open_ports.append(port)
        sock.close()
    
    result_text.config(state=NORMAL)
    result_text.insert(tk.END, f"Open Ports: {', '.join(map(str, open_ports)) if open_ports else 'None Found'}\n")
    result_text.config(state=DISABLED)

# Function to check email spam risk
def check_email_spam():
    sender_email = email_entry.get()
    try:
        domain = sender_email.split('@')[1]
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            result = f"[+] Email Domain Found: {domain}\n[+] MX Records: {len(mx_records)}\n"
        except dns.resolver.NoAnswer:
            result = f"[-] No MX records found! This domain may not be able to send emails.\n"
        
        blacklist_url = f"https://www.spamhaus.org/query/domain/{domain}"
        response = requests.get(blacklist_url)
        if "is listed in the DBL" in response.text:
            result += f"[-] WARNING! {domain} is blacklisted for spam!\n"
        else:
            result += f"[+] {domain} is NOT blacklisted.\n"
        
        result_text.config(state=NORMAL)
        result_text.insert(tk.END, result + "\n")
        result_text.config(state=DISABLED)
    except Exception as e:
        result_text.config(state=NORMAL)
        result_text.insert(tk.END, f"[-] Error: {e}\n")
        result_text.config(state=DISABLED)

# Function to check for SQL Injection vulnerability
def check_sql_injection():
    url = website_entry.get()
    payload = "' OR '1'='1"
    try:
        response = requests.get(url + "?id=" + payload)
        if "error" in response.text.lower() or "sql" in response.text.lower():
            result_text.config(state=NORMAL)
            result_text.insert(tk.END, "[!] Possible SQL Injection vulnerability detected!\n")
            result_text.config(state=DISABLED)
        else:
            result_text.config(state=NORMAL)
            result_text.insert(tk.END, "[+] No SQL Injection vulnerability found.\n")
            result_text.config(state=DISABLED)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to check SQL Injection: {e}")

# Function to check for XSS vulnerability
def check_xss():
    url = website_entry.get()
    payload = "<script>alert('XSS')</script>"
    try:
        response = requests.get(url + "?q=" + payload)
        if payload in response.text:
            result_text.config(state=NORMAL)
            result_text.insert(tk.END, "[!] Possible XSS vulnerability detected!\n")
            result_text.config(state=DISABLED)
        else:
            result_text.config(state=NORMAL)
            result_text.insert(tk.END, "[+] No XSS vulnerability found.\n")
            result_text.config(state=DISABLED)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to check XSS: {e}")

# GUI Setup
root = tk.Tk()
root.title("Security Scanner & Email Spam Checker")
root.geometry("500x650")
root.configure(bg="#2C3E50")

frame = tk.Frame(root, bg="#34495E", padx=10, pady=10)
frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

website_label = tk.Label(frame, text="Enter Website:", bg="#34495E", fg="white", font=("Arial", 12, "bold"))
website_label.pack()
website_entry = tk.Entry(frame, width=50)
website_entry.pack(pady=5)

scan_button = tk.Button(frame, text="Scan Website", command=scan_website)
scan_button.pack(pady=5)
port_button = tk.Button(frame, text="Scan Open Ports", command=scan_ports)
port_button.pack(pady=5)
sql_button = tk.Button(frame, text="Check SQL Injection", command=check_sql_injection)
sql_button.pack(pady=5)
xss_button = tk.Button(frame, text="Check XSS", command=check_xss)
xss_button.pack(pady=5)

email_label = tk.Label(frame, text="Enter Email:", bg="#34495E", fg="white", font=("Arial", 12, "bold"))
email_label.pack(pady=5)
email_entry = tk.Entry(frame, width=50)
email_entry.pack(pady=5)
email_button = tk.Button(frame, text="Check Email Spam", command=check_email_spam)
email_button.pack(pady=5)

result_text = scrolledtext.ScrolledText(frame, height=12, wrap=tk.WORD, bg="#ECF0F1", fg="#2C3E50", font=("Arial", 10))
result_text.pack(pady=10, fill=tk.BOTH, expand=True)
result_text.config(state=DISABLED)

root.mainloop()
