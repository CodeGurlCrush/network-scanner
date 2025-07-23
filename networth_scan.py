import ipaddress
from scapy.all import IP, ICMP, sr1, conf
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import threading
import time
import re

# === Utility ===

def is_valid_cidr(ip_range):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    return re.match(pattern, ip_range)

# === Scanner Function ===

def scan_network(ip_range, output_box, timeout=0.3, delay=0.05):
    conf.verb = 0  # Suppress scapy output

    try:
        network = ipaddress.ip_network(ip_range, strict=False)
    except ValueError as e:
        messagebox.showerror("Invalid IP Range", str(e))
        return

    output_box.delete(1.0, tk.END)
    output_box.insert(tk.END, f"[*] Scanning {ip_range}...\n\n")

    up_hosts = []
    down_hosts = []

    start_time = time.time()

    for ip in network.hosts():
        ip = str(ip)
        try:
            output_box.insert(tk.END, f"Pinging {ip}... ")
            output_box.see(tk.END)
            output_box.update()

            pkt = IP(dst=ip) / ICMP()
            resp = sr1(pkt, timeout=timeout)

            if resp is None:
                output_box.insert(tk.END, "Down\n")
                down_hosts.append(ip)
            else:
                output_box.insert(tk.END, "Up\n")
                up_hosts.append(ip)

            output_box.see(tk.END)
            output_box.update()
            time.sleep(delay)

        except PermissionError:
            output_box.insert(tk.END, "Permission Denied (Run as admin/root)\n")
            down_hosts.append(ip)
            continue

        except Exception as e:
            output_box.insert(tk.END, f"Error scanning {ip}: {e}\n")
            down_hosts.append(ip)
            continue

    end_time = time.time()
    duration = end_time - start_time

    output_box.insert(tk.END, "\n=== Scan Summary ===\n")
    output_box.insert(tk.END, f"Total Hosts Scanned: {len(up_hosts) + len(down_hosts)}\n")
    output_box.insert(tk.END, f"Systems Up        : {len(up_hosts)}\n")
    output_box.insert(tk.END, f"Systems Down      : {len(down_hosts)}\n")
    output_box.insert(tk.END, f"Scan Duration     : {duration:.2f} seconds\n")

    if up_hosts:
        output_box.insert(tk.END, "\nUp Hosts:\n")
        for host in up_hosts:
            output_box.insert(tk.END, f" - {host}\n")
    output_box.see(tk.END)

# === GUI Handlers ===

def start_scan(entry, output_box):
    ip_range = entry.get().strip()
    if not ip_range:
        messagebox.showwarning("Input Required", "Please enter an IP range.")
        return
    if not is_valid_cidr(ip_range):
        messagebox.showwarning("Invalid Format", "Enter CIDR format like 192.168.1.0/24.")
        return
    threading.Thread(target=scan_network, args=(ip_range, output_box), daemon=True).start()

def clear_output(output_box):
    output_box.delete(1.0, tk.END)

def save_results(output_box):
    content = output_box.get(1.0, tk.END)
    if not content.strip():
        messagebox.showinfo("No Data", "There is nothing to save.")
        return
    file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file:
        with open(file, "w") as f:
            f.write(content)
        messagebox.showinfo("Saved", f"Results saved to {file}")

# === GUI ===

def create_gui():
    window = tk.Tk()
    window.title("Python Network Scanner")
    window.geometry("700x550")
    window.resizable(False, False)

    tk.Label(window, text="Enter IP Range (e.g. 192.168.1.0/24):", font=("Segoe UI", 10)).pack(pady=5)
    ip_entry = tk.Entry(window, width=50, font=("Segoe UI", 10))
    ip_entry.pack(pady=5)

    btn_frame = tk.Frame(window)
    btn_frame.pack(pady=10)

    tk.Button(btn_frame, text="Start Scan", command=lambda: start_scan(ip_entry, output_box), width=15).pack(side=tk.LEFT, padx=5)
    tk.Button(btn_frame, text="Clear Output", command=lambda: clear_output(output_box), width=15).pack(side=tk.LEFT, padx=5)
    tk.Button(btn_frame, text="Save Results", command=lambda: save_results(output_box), width=15).pack(side=tk.LEFT, padx=5)

    output_box = scrolledtext.ScrolledText(window, width=85, height=25, font=("Consolas", 9))
    output_box.pack(pady=10)

    window.mainloop()

# === Main ===

if __name__ == "__main__":
    create_gui()
