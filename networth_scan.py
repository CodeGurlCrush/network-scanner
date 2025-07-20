import ipaddress
from scapy.all import IP, ICMP, sr1, conf
import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading
import time

def scan_network(ip_range, output_box, timeout=0.3, delay=0.05):
    conf.verb = 0  # disable verbose mode in scapy
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
    except ValueError as e:
        messagebox.showerror("Invalid IP Range", str(e))
        return

    output_box.delete(1.0, tk.END)
    output_box.insert(tk.END, f"[*] Scanning {ip_range}...\n\n")

    up_hosts = []
    down_hosts = []

    for ip in network.hosts():
        ip = str(ip)
        try:
            output_box.insert(tk.END, f"Pinging {ip}... ")
            output_box.see(tk.END)
            output_box.update()

            pkt = IP(dst=ip)/ICMP()
            resp = sr1(pkt, timeout=timeout)

            if resp is None:
                output_box.insert(tk.END, "Down\n")
                down_hosts.append(ip)
            else:
                output_box.insert(tk.END, "Up\n")
                up_hosts.append(ip)

            output_box.see(tk.END)
            output_box.update()
            time.sleep(delay)  # Delay to avoid spamming

        except Exception as e:
            output_box.insert(tk.END, f"Error scanning {ip}: {e}\n")
            output_box.see(tk.END)
            output_box.update()

    output_box.insert(tk.END, "\n=== Scan Summary ===\n")
    output_box.insert(tk.END, f"Total Hosts Scanned: {len(up_hosts) + len(down_hosts)}\n")
    output_box.insert(tk.END, f"Systems Up        : {len(up_hosts)}\n")
    output_box.insert(tk.END, f"Systems Down      : {len(down_hosts)}\n")
    if up_hosts:
        output_box.insert(tk.END, "\nUp Hosts:\n")
        for host in up_hosts:
            output_box.insert(tk.END, f" - {host}\n")
    output_box.see(tk.END)

def start_scan(entry, output_box):
    ip_range = entry.get().strip()
    if not ip_range:
        messagebox.showwarning("Input Required", "Please enter an IP range.")
        return
    threading.Thread(target=scan_network, args=(ip_range, output_box), daemon=True).start()

def create_gui():
    window = tk.Tk()
    window.title("Python Network Scanner")
    window.geometry("600x500")

    tk.Label(window, text="Enter IP Range (e.g. 192.168.1.0/24):").pack(pady=5)
    ip_entry = tk.Entry(window, width=40)
    ip_entry.pack(pady=5)

    tk.Button(window, text="Start Scan", command=lambda: start_scan(ip_entry, output_box)).pack(pady=10)

    output_box = scrolledtext.ScrolledText(window, width=70, height=20)
    output_box.pack(pady=10)

    window.mainloop()

if __name__ == "__main__":
    create_gui()
