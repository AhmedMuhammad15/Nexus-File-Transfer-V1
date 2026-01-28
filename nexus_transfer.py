import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import socket
import multiprocessing
import threading
import time
import os
import http.server
import socketserver
import datetime
import shutil
import subprocess

# --- SETTINGS & CONSTANTS ---
BROADCAST_IP = '<broadcast>'
DISCOVERY_PORT = 50001
FILE_PORT = 50002
HTTP_PORT = 8000
BUFFER_SIZE = 4096
MAGIC_MSG = b"SMIU_PROJECT_SECURE_HANDSHAKE"

# ==========================================
#  BACKEND PROCESS (CORE LOGIC)
# ==========================================
def backend_process(queue_to_gui, queue_from_gui):
    httpd = None
    detected_devices = {} 

    def log(message):
        """Standardized Logging with Timestamp"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        queue_to_gui.put({"type": "LOG", "msg": f"[{timestamp}] {message}"})

    def get_local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def scan_usb_drives():
        """ Detects USB drives using Windows WMI """
        while True:
            try:
                # WMI Command to find Removable Disks (DriveType=2)
                cmd = "wmic logicaldisk where drivetype=2 get deviceid, volumename"
                output = subprocess.check_output(cmd, shell=True).decode()
                drives = []
                lines = output.split('\n')
                for line in lines[1:]: 
                    if line.strip():
                        parts = line.split()
                        drive_letter = parts[0]
                        drives.append(drive_letter)
                queue_to_gui.put({"type": "USB_UPDATE", "drives": drives})
            except Exception as e:
                pass 
            time.sleep(2) 

    def start_http_server(filepath):
        nonlocal httpd
        directory, filename = os.path.split(filepath)
        os.chdir(directory)
        handler = http.server.SimpleHTTPRequestHandler
        socketserver.TCPServer.allow_reuse_address = True
        try:
            httpd = socketserver.TCPServer(("0.0.0.0", HTTP_PORT), handler)
            local_ip = get_local_ip()
            link = f"http://{local_ip}:{HTTP_PORT}/{filename}"
            
            queue_to_gui.put({"type": "HTTP_STARTED", "link": link})
            log(f"HTTP Server started. Hosting: {filename}")
            log(f"Access Link: {link}")
            httpd.serve_forever()
        except Exception as e:
            queue_to_gui.put({"type": "HTTP_ERROR", "error": str(e)})
            log(f"HTTP Server Error: {e}")

    def stop_http_server():
        nonlocal httpd
        if httpd:
            httpd.shutdown()
            httpd.server_close()
            httpd = None
            queue_to_gui.put({"type": "HTTP_STOPPED"})
            log("HTTP Server stopped by user.")

    def listen_for_discovery():
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            udp_sock.bind(('', DISCOVERY_PORT))
        except:
            log(f"Error: Port {DISCOVERY_PORT} is busy.")
            return 
        while True:
            try:
                data, addr = udp_sock.recvfrom(1024)
                if data == MAGIC_MSG and addr[0] != get_local_ip():
                    if addr[0] not in detected_devices:
                        detected_devices[addr[0]] = time.time()
                        queue_to_gui.put({"type": "NEW_DEVICE", "ip": addr[0]})
                        log(f"New Device Discovered: {addr[0]}")
            except:
                pass

    def broadcast_presence():
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while True:
            try:
                udp_sock.sendto(MAGIC_MSG, (BROADCAST_IP, DISCOVERY_PORT))
                time.sleep(2)
            except:
                pass

    def send_file_tcp(target_ip, filepath):
        filename = os.path.basename(filepath)
        log(f"Initiating TCP handshake with {target_ip}...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target_ip, FILE_PORT))
            
            # Protocol: Send Filename -> Wait for ACK -> Send Data
            s.send(filename.encode())
            s.recv(1024) # ACK
            
            log(f"Sending data for: {filename}")
            with open(filepath, "rb") as f:
                while True:
                    data = f.read(BUFFER_SIZE)
                    if not data: break
                    s.sendall(data)
            s.close()
            queue_to_gui.put({"type": "SEND_SUCCESS", "file": filename})
            log(f"Transfer Complete: {filename}")
        except Exception as e:
            queue_to_gui.put({"type": "SEND_ERROR", "error": str(e)})
            log(f"Transfer Failed: {e}")

    def start_file_receiver():
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(('0.0.0.0', FILE_PORT))
        server_sock.listen(5)
        log(f"TCP Listener active on Port {FILE_PORT}")
        
        while True:
            client, addr = server_sock.accept()
            log(f"Incoming Connection from {addr[0]}")
            try:
                fname = client.recv(1024).decode()
                client.send(b"ACK") 
                
                safe_name = "received_" + os.path.basename(fname)
                with open(safe_name, "wb") as f:
                    while True:
                        data = client.recv(BUFFER_SIZE)
                        if not data: break
                        f.write(data)
                client.close()
                queue_to_gui.put({"type": "FILE_RECEIVED", "filename": safe_name})
                log(f"File Received & Saved: {safe_name}")
            except Exception as e:
                log(f"Receive Error: {e}")
                client.close()

    # --- Start Background Threads ---
    threading.Thread(target=listen_for_discovery, daemon=True).start()
    threading.Thread(target=broadcast_presence, daemon=True).start()
    threading.Thread(target=start_file_receiver, daemon=True).start()
    threading.Thread(target=scan_usb_drives, daemon=True).start() 

    # --- Main Backend Loop ---
    while True:
        try:
            msg = queue_from_gui.get()
            if msg['type'] == "START_HTTP":
                if httpd: stop_http_server()
                threading.Thread(target=start_http_server, args=(msg['filepath'],), daemon=True).start()
            elif msg['type'] == "STOP_HTTP":
                if httpd: threading.Thread(target=stop_http_server).start()
            elif msg['type'] == "SEND_FILE_TCP":
                threading.Thread(target=send_file_tcp, args=(msg['ip'], msg['filepath']), daemon=True).start()
            elif msg['type'] == "COPY_TO_USB":
                try:
                    src = msg['filepath']
                    dest_drive = msg['drive']
                    filename = os.path.basename(src)
                    dest_path = os.path.join(dest_drive, filename)
                    
                    log(f"System Call: Copying {filename} to {dest_drive}...")
                    shutil.copy2(src, dest_path)
                    queue_to_gui.put({"type": "USB_SUCCESS", "file": filename})
                    log("USB Write Operation Successful.")
                except Exception as e:
                    log(f"USB Write Failed: {e}")
                    queue_to_gui.put({"type": "USB_ERROR", "error": str(e)})
        except:
            pass

# ==========================================
#  FRONTEND GUI (PROFESSIONAL THEME)
# ==========================================
class FileShareApp:
    def __init__(self, root, queue_in, queue_out):
        self.root = root
        self.queue_in = queue_in
        self.queue_out = queue_out
        
        # --- Color Palette ---
        self.bg_color = "#2b2b2b"    # Dark Grey
        self.fg_color = "#ffffff"    # White
        self.accent_blue = "#007acc" # Professional Blue
        self.accent_green = "#28a745"
        self.accent_orange = "#d35400"
        self.list_bg = "#333333"
        
        self.root.title("NexusTransfer-Core-V1")
        self.root.geometry("780x580")
        self.root.configure(bg=self.bg_color)
        
        # --- Styling ---
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TNotebook", background=self.bg_color, borderwidth=0)
        style.configure("TNotebook.Tab", background="#444444", foreground="white", padding=[20, 10], font=("Segoe UI", 10))
        style.map("TNotebook.Tab", background=[("selected", self.accent_blue)], foreground=[("selected", "white")])
        style.configure("TFrame", background=self.bg_color)
        
        # --- Tabs ---
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(pady=15, padx=15, fill=tk.BOTH, expand=True)
        
        self.tab_laptop = ttk.Frame(self.notebook)
        self.tab_mobile = ttk.Frame(self.notebook)
        self.tab_usb = ttk.Frame(self.notebook)
        self.tab_logs = ttk.Frame(self.notebook)
        
        self.notebook.add(self.tab_laptop, text=" Network Discovery ")
        self.notebook.add(self.tab_mobile, text=" Mobile Link (HTTP) ")
        self.notebook.add(self.tab_usb, text=" USB Manager (WMI) ")
        self.notebook.add(self.tab_logs, text=" Kernel Logs ")

        self.setup_laptop_tab()
        self.setup_mobile_tab()
        self.setup_usb_tab()
        self.setup_logs_tab()
        
        self.check_ipc()

    def create_btn(self, parent, text, command, color):
        return tk.Button(parent, text=text, command=command,
                         bg=color, fg="white", font=("Segoe UI", 10, "bold"),
                         relief="flat", bd=0, activebackground="#555555",
                         activeforeground="white", cursor="hand2", padx=20, pady=8)

    def setup_laptop_tab(self):
        tk.Label(self.tab_laptop, text="Discovered Peers (UDP Broadcast)", 
                 bg=self.bg_color, fg="#aaaaaa", font=("Segoe UI", 12)).pack(pady=(20, 5))
        
        self.listbox = tk.Listbox(self.tab_laptop, height=7, bg=self.list_bg, fg="white", 
                                  font=("Consolas", 11), relief="flat", 
                                  selectbackground=self.accent_blue, activestyle="none")
        self.listbox.pack(fill=tk.BOTH, padx=50, pady=5)
        
        frame_manual = tk.Frame(self.tab_laptop, bg=self.bg_color)
        frame_manual.pack(pady=10)
        tk.Label(frame_manual, text="Manual IP Override: ", bg=self.bg_color, fg="#888888", font=("Segoe UI", 10)).pack(side=tk.LEFT)
        self.entry_manual_ip = tk.Entry(frame_manual, width=20, bg=self.list_bg, fg="white", 
                                        insertbackground="white", relief="flat", font=("Segoe UI", 10))
        self.entry_manual_ip.pack(side=tk.LEFT, padx=10, ipady=4)
        
        self.create_btn(self.tab_laptop, "Send Files", self.on_send_laptop, self.accent_green).pack(pady=15)

    def setup_mobile_tab(self):
        tk.Label(self.tab_mobile, text="Host File for Mobile Browser", 
                 bg=self.bg_color, fg="white", font=("Segoe UI", 16, "bold")).pack(pady=(40, 20))
        
        self.btn_host = self.create_btn(self.tab_mobile, "SELECT FILE & HOST", self.on_host_click, self.accent_blue)
        self.btn_host.pack(pady=10)
        
        self.entry_link = tk.Entry(self.tab_mobile, font=("Consolas", 14), justify='center', 
                                   bg=self.list_bg, fg=self.accent_blue, relief="flat", insertbackground="white")
        self.entry_link.pack(fill=tk.X, padx=100, pady=20, ipady=8)
        
        self.btn_stop_host = self.create_btn(self.tab_mobile, "STOP SERVER", self.on_stop_host, "#c0392b")
        self.btn_stop_host.config(state=tk.DISABLED)
        self.btn_stop_host.pack(pady=5)

    def setup_usb_tab(self):
        tk.Label(self.tab_usb, text="Detected Removable Media", 
                 bg=self.bg_color, fg="white", font=("Segoe UI", 14, "bold")).pack(pady=(30, 10))
        
        self.usb_listbox = tk.Listbox(self.tab_usb, height=6, bg=self.list_bg, fg="white",
                                      font=("Consolas", 11), relief="flat", 
                                      selectbackground=self.accent_orange, activestyle="none")
        self.usb_listbox.pack(fill=tk.BOTH, padx=80, pady=10)
        
        tk.Label(self.tab_usb, text="* Auto-detected via 'wmic' system call", 
                 bg=self.bg_color, fg="#888888", font=("Segoe UI", 9, "italic")).pack()
        
        self.create_btn(self.tab_usb, "Send Files", self.on_usb_copy, self.accent_orange).pack(pady=25)

    def setup_logs_tab(self):
        self.log_text = tk.Text(self.tab_logs, state='disabled', bg="#1e1e1e", fg="#00FF00", 
                                font=("Consolas", 9), relief="flat", padx=10, pady=10)
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def log_gui(self, message):
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')

    # --- ACTIONS ---
    def on_send_laptop(self):
        selection = self.listbox.curselection()
        target_ip = self.listbox.get(selection[0]) if selection else self.entry_manual_ip.get()
        if not target_ip:
            messagebox.showwarning("Target Error", "Please select a device or enter a Manual IP.")
            return
        filepath = filedialog.askopenfilename()
        if filepath: self.queue_out.put({"type": "SEND_FILE_TCP", "ip": target_ip, "filepath": filepath})

    def on_host_click(self):
        filepath = filedialog.askopenfilename()
        if filepath: self.queue_out.put({"type": "START_HTTP", "filepath": filepath})

    def on_stop_host(self):
        self.queue_out.put({"type": "STOP_HTTP"})

    def on_usb_copy(self):
        selection = self.usb_listbox.curselection()
        if not selection:
            messagebox.showwarning("Selection Error", "Please select a USB drive from the list.")
            return
        drive_letter = self.usb_listbox.get(selection[0]).strip()
        filepath = filedialog.askopenfilename()
        if filepath:
            self.queue_out.put({"type": "COPY_TO_USB", "drive": drive_letter, "filepath": filepath})

    def check_ipc(self):
        while not self.queue_in.empty():
            msg = self.queue_in.get_nowait()
            
            if msg['type'] == "LOG": self.log_gui(msg['msg'])
            elif msg['type'] == "USB_UPDATE":
                current_items = self.usb_listbox.get(0, tk.END)
                new_items = tuple(msg['drives'])
                if current_items != new_items:
                    self.usb_listbox.delete(0, tk.END)
                    for drive in msg['drives']: self.usb_listbox.insert(tk.END, drive)
            elif msg['type'] == "NEW_DEVICE":
                current = self.listbox.get(0, tk.END)
                if msg['ip'] not in current: self.listbox.insert(tk.END, msg['ip'])
            elif msg['type'] == "HTTP_STARTED":
                self.entry_link.delete(0, tk.END)
                self.entry_link.insert(0, msg['link'])
                self.btn_stop_host.config(state=tk.NORMAL)
                self.btn_host.config(state=tk.DISABLED)
                messagebox.showinfo("Server Online", f"Hosting active at:\n{msg['link']}")
            elif msg['type'] == "HTTP_STOPPED":
                self.entry_link.delete(0, tk.END)
                self.btn_stop_host.config(state=tk.DISABLED)
                self.btn_host.config(state=tk.NORMAL)
            elif msg['type'] == "SEND_SUCCESS": messagebox.showinfo("Transfer Complete", f"File '{msg['file']}' sent successfully.")
            elif msg['type'] == "USB_SUCCESS": messagebox.showinfo("Write Complete", f"File '{msg['file']}' copied to USB.")
            elif msg['type'] == "USB_ERROR": messagebox.showerror("I/O Error", msg['error'])
            elif msg['type'] == "FILE_RECEIVED": messagebox.showinfo("Inbound File", f"Received file: {msg['filename']}")

        self.root.after(100, self.check_ipc)

if __name__ == "__main__":
    multiprocessing.freeze_support() # Important for Windows
    q_to_gui = multiprocessing.Queue()
    q_from_gui = multiprocessing.Queue()
    backend = multiprocessing.Process(target=backend_process, args=(q_to_gui, q_from_gui))
    backend.daemon = True
    backend.start()
    
    root = tk.Tk()
    app = FileShareApp(root, q_to_gui, q_from_gui)
    try:
        root.mainloop()
    except:
        pass
    finally:
        backend.terminate()