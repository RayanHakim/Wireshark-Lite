import tkinter as tk
from tkinter import ttk, messagebox
import threading
import socket
import sniffer_core

class WiresharkLite:
    def __init__(self, root):
        self.root = root
        self.root.title("Wireshark Lite")
        self.root.geometry("900x600")
        
        # Kontrol State
        self.stop_event = threading.Event()
        self.is_running = False
        self.packet_history = {} # Simpan data paket berdasarkan ID tabel

        # --- UI SETUP ---
        control_frame = tk.Frame(root)
        control_frame.pack(pady=10, fill=tk.X)

        self.btn_start = tk.Button(control_frame, text="START", bg="green", fg="white", width=12, command=self.toggle_sniffing)
        self.btn_start.pack(side=tk.LEFT, padx=10)

        self.btn_clear = tk.Button(control_frame, text="CLEAR SCREEN", bg="orange", width=12, command=self.clear_table)
        self.btn_clear.pack(side=tk.LEFT, padx=5)

        tk.Label(control_frame, text="Filter Protocol:").pack(side=tk.LEFT, padx=(15, 0))
        self.filter_var = tk.StringVar(value="ALL")
        combo = ttk.Combobox(control_frame, textvariable=self.filter_var, values=["ALL", "TCP", "UDP", "ICMP"], width=10, state="readonly")
        combo.pack(side=tk.LEFT, padx=5)

        # Tabel Utama
        columns = ("no", "src", "dst", "proto", "len")
        self.tree = ttk.Treeview(root, columns=columns, show="headings")
        self.tree.heading("no", text="No")
        self.tree.heading("src", text="Source IP")
        self.tree.heading("dst", text="Destination IP")
        self.tree.heading("proto", text="Protocol")
        self.tree.heading("len", text="Length (Bytes)")
        
        self.tree.column("no", width=50, anchor="center")
        self.tree.column("proto", width=100, anchor="center")
        
        self.tree.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Binding Double Click
        self.tree.bind("<Double-1>", self.on_double_click)
        
        self.pkt_count = 0
        self.print_status("Siap melakukan sniffing. Klik START (Gunakan akses Admin).")

    def print_status(self, msg):
        """Menampilkan status di console bawah (opsional)"""
        print(f"[*] {msg}")

    def on_double_click(self, event):
        """Membuka detail paket saat baris tabel di-klik 2x"""
        selection = self.tree.selection()
        if not selection: return
        
        item_id = selection[0]
        data = self.packet_history[item_id]
        pkt = data['raw_pkt']

        # Jendela Detail Baru (Pop-up)
        detail_win = tk.Toplevel(self.root)
        detail_win.title(f"Detail Paket #{self.tree.item(item_id)['values'][0]}")
        detail_win.geometry("700x500")

        # Cek Whois Sederhana (Reverse DNS)
        try:
            hostname = socket.gethostbyaddr(data['dst'])[0]
        except:
            hostname = "Unknown Host"

        text_area = tk.Text(detail_win, padx=10, pady=10, font=("Consolas", 10), bg="#f4f4f4")
        text_area.pack(fill=tk.BOTH, expand=True)

        # Susun Informasi Detail
        info = f"SOURCE      : {data['src']}\n"
        info += f"DESTINATION : {data['dst']} ({hostname})\n"
        info += f"PROTOCOL    : {data['proto']}\n"
        info += f"LENGTH      : {data['len']} Bytes\n"
        info += "-"*50 + "\n"
        info += "--- DECODE LAYERS ---\n"
        info += pkt.show(dump=True) # Fungsi Scapy untuk bedah semua layer
        info += "\n" + "-"*50 + "\n"
        info += "--- RAW DATA (HEX) ---\n"
        info += bytes(pkt).hex(' ') # Menampilkan data mentah dalam bentuk hex

        text_area.insert(tk.END, info)
        text_area.config(state=tk.DISABLED) # Kunci teks agar tidak bisa diedit

    def add_to_table(self, data):
        """Menambah data ke tabel GUI dari thread sniffer"""
        self.pkt_count += 1
        item_id = self.tree.insert("", tk.END, values=(
            self.pkt_count, 
            data['src'], 
            data['dst'], 
            data['proto'], 
            data['len']
        ))
        # Simpan objek paket asli ke memori dictionary
        self.packet_history[item_id] = data
        self.tree.yview_moveto(1) # Auto-scroll ke bawah

    def toggle_sniffing(self):
        if not self.is_running:
            self.is_running = True
            self.stop_event.clear()
            self.btn_start.config(text="STOP", bg="red")
            self.btn_clear.config(state=tk.DISABLED)
            
            # Threading agar GUI tidak 'Freeze'
            t = threading.Thread(target=self.run_sniffer, daemon=True)
            t.start()
        else:
            self.is_running = False
            self.stop_event.set()
            self.btn_start.config(text="START", bg="green")
            self.btn_clear.config(state=tk.NORMAL)

    def run_sniffer(self):
        try:
            sniffer_core.start_sniffing(self.add_to_table, self.stop_event, self.filter_var.get())
        except Exception as e:
            messagebox.showerror("Permission Error", f"Gagal akses Network Interface.\n{e}")
            self.is_running = False
            self.btn_start.config(text="START", bg="green")

    def clear_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.packet_history.clear()
        self.pkt_count = 0

if __name__ == "__main__":
    root = tk.Tk()
    app = WiresharkLite(root)
    root.mainloop()