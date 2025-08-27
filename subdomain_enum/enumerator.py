import requests
import threading
import os
import dns.resolver
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, ttk

class SubdomainAndDNSLookupTool:
    def __init__(self, master):
        self.master = master
        master.title("Advanced Subdomain & DNS Tool")
        master.geometry("800x700")
        master.configure(bg='#f0f0f0')
        
        # Set window icon
        try:
            master.iconbitmap('icon.ico')
        except:
            pass
        
        # Custom style
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TButton', font=('Helvetica', 10), padding=6)
        self.style.configure('TLabel', background='#f0f0f0', font=('Helvetica', 10))
        self.style.configure('Header.TLabel', font=('Helvetica', 12, 'bold'), foreground='#2c3e50')
        
        # Main frame
        self.main_frame = ttk.Frame(master, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        self.header = ttk.Label(self.main_frame, text="SUBDOMAIN & DNS ENUMERATOR", style='Header.TLabel')
        self.header.pack(pady=(0, 10))
        
        # Domain input frame
        self.input_frame = ttk.Frame(self.main_frame)
        self.input_frame.pack(fill=tk.X, pady=5)
        
        self.domain_label = ttk.Label(self.input_frame, text="Domain to analyze:")
        self.domain_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.domain_entry = ttk.Entry(self.input_frame, width=40)
        self.domain_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
        
        # File selection frame
        self.file_frame = ttk.Frame(self.main_frame)
        self.file_frame.pack(fill=tk.X, pady=5)
        
        self.file_button = ttk.Button(self.file_frame, text="Select Subdomain File", command=self.load_file)
        self.file_button.pack(side=tk.LEFT)
        
        self.file_label = ttk.Label(self.file_frame, text="No file selected", foreground='#7f8c8d')
        self.file_label.pack(side=tk.LEFT, padx=10)
        
        # Button frame
        self.button_frame = ttk.Frame(self.main_frame)
        self.button_frame.pack(fill=tk.X, pady=10)
        
        self.enumerate_button = ttk.Button(self.button_frame, text="▶ Enumerate Subdomains", 
                                         command=self.enumerate_subdomains)
        self.enumerate_button.pack(side=tk.LEFT, expand=True, padx=5)
        
        self.ns_button = ttk.Button(self.button_frame, text="▶ DNS Records Lookup", 
                                  command=self.dns_lookup)
        self.ns_button.pack(side=tk.LEFT, expand=True, padx=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, 
                                   relief=tk.SUNKEN, anchor=tk.W, foreground='#34495e')
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))
        
        # Results area
        self.result_frame = ttk.Frame(self.main_frame)
        self.result_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        self.result_text = scrolledtext.ScrolledText(self.result_frame, width=90, height=30, 
                                                   wrap=tk.WORD, font=('Consolas', 10),
                                                   padx=10, pady=10)
        self.result_text.pack(fill=tk.BOTH, expand=True)
        
        # Initialize variables
        self.filename = None
        self.discovered_subdomains = []
        self.lock = threading.Lock()
        
        # Set focus to domain entry
        self.domain_entry.focus()

    def load_file(self):
        self.filename = filedialog.askopenfilename(title="Select Subdomain File", 
                                                  filetypes=[("Text files", "*.txt")])
        if self.filename:
            self.file_label.config(text=os.path.basename(self.filename))
            self.status_var.set(f"Loaded: {os.path.basename(self.filename)}")

    def check_subdomain(self, subdomain, domain):
        url = f'http://{subdomain}.{domain}'
        try:
            requests.get(url, timeout=5)
        except (requests.ConnectionError, requests.Timeout):
            pass
        else:
            with self.lock:
                self.discovered_subdomains.append(url)
                self.result_text.insert(tk.END, f"[+] Discovered: {url}\n")
                self.result_text.see(tk.END)
                self.status_var.set(f"Discovered: {url}")

    def enumerate_subdomains(self):
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Input Error", "Please enter a domain name.")
            return
        if not self.filename:
            messagebox.showerror("Input Error", "Please select a subdomain file.")
            return

        self.discovered_subdomains.clear()
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"= Starting subdomain enumeration for {domain} =\n\n")
        
        try:
            with open(self.filename) as file:
                subdomains = file.read().splitlines()
        except Exception as e:
            messagebox.showerror("File Error", f"Failed to read subdomain file:\n{str(e)}")
            return

        self.status_var.set("Enumerating subdomains...")
        self.enumerate_button.config(state=tk.DISABLED)
        
        threads = []
        for subdomain in subdomains:
            thread = threading.Thread(target=self.check_subdomain, args=(subdomain, domain))
            thread.start()
            threads.append(thread)

        # Wait for threads to complete in a separate thread to keep GUI responsive
        def check_threads():
            alive = sum(1 for t in threads if t.is_alive())
            if alive > 0:
                self.status_var.set(f"Scanning... ({alive} threads remaining)")
                self.master.after(100, check_threads)
            else:
                count = len(self.discovered_subdomains)
                self.result_text.insert(tk.END, f"\n= Scan complete. Found {count} subdomains =\n")
                self.result_text.insert(tk.END, "Results saved to 'discovered_subdomains.txt'\n")
                with open("discovered_subdomains.txt", 'w') as f:
                    f.write('\n'.join(self.discovered_subdomains))
                self.status_var.set(f"Ready | Found {count} subdomains")
                self.enumerate_button.config(state=tk.NORMAL)

        self.master.after(100, check_threads)

    def dns_lookup(self):
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Input Error", "Please enter a domain name.")
            return

        records_type = ['A', 'AAAA', 'NS', 'MX', 'TXT', 'CNAME', 'SOA']
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"= DNS records for {domain} =\n\n")
        self.status_var.set(f"Looking up DNS records for {domain}...")
        
        resolver = dns.resolver.Resolver()
        found_records = False
        
        for record_type in records_type:
            try:
                answer = resolver.resolve(domain, record_type)
                self.result_text.insert(tk.END, f"=== {record_type} Records ===\n")
                for data in answer:
                    self.result_text.insert(tk.END, f"{data}\n")
                self.result_text.insert(tk.END, "\n")
                found_records = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except Exception as e:
                self.result_text.insert(tk.END, f"Error retrieving {record_type} records: {str(e)}\n")

        if not found_records:
            self.result_text.insert(tk.END, "No DNS records found for the domain\n")
        
        self.result_text.insert(tk.END, "\n= DNS lookup complete =\n")
        self.status_var.set("DNS lookup completed")

if __name__ == "__main__":
    root = tk.Tk()
    app = SubdomainAndDNSLookupTool(root)
    root.mainloop()
