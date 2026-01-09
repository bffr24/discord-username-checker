import tkinter as tk
from tkinter import ttk, messagebox
import threading
import random
import string
import requests
import time
import queue
import yaml
import os

class DiscordUsernameChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("Discord Username Checker")
        self.root.geometry("800x680")
        self.root.resizable(False, False)

        self.running = False
        self.stop_event = threading.Event()
        self.threads = []

        self.lock = threading.Lock()  # To protect shared data
        self.tried_usernames = set()  # Prevent duplicates of random usernames only

        self.custom_queue = queue.Queue()

        self.config_file = "config.yaml"
        self.config = {}
        self.load_config()

        self.create_widgets()
        self.apply_config_to_widgets()

    def create_widgets(self):
        pad = 10

        # Webhook Fields
        webhook_frame = ttk.LabelFrame(self.root, text="Webhooks")
        webhook_frame.place(x=pad, y=pad, width=780, height=70)

        ttk.Label(webhook_frame, text="Random Webhook:").place(x=10, y=5)
        self.webhook_random_entry = ttk.Entry(webhook_frame)
        self.webhook_random_entry.place(x=140, y=5, width=620, height=20)

        ttk.Label(webhook_frame, text="Custom Webhook:").place(x=10, y=35)
        self.webhook_custom_entry = ttk.Entry(webhook_frame)
        self.webhook_custom_entry.place(x=140, y=35, width=620, height=20)

        # Proxy Field
        proxy_frame = ttk.LabelFrame(self.root, text="Proxies (ip:port or user:pass@ip:port)")
        proxy_frame.place(x=pad, y=90, width=380, height=120)
        self.proxy_text = tk.Text(proxy_frame, height=6, width=47)
        self.proxy_text.pack(padx=5, pady=5)

        # Custom username list
        custom_frame = ttk.LabelFrame(self.root, text="Custom Usernames (one per line)")
        custom_frame.place(x=400, y=90, width=380, height=120)
        self.custom_text = tk.Text(custom_frame, height=6, width=47)
        self.custom_text.pack(padx=5, pady=5)

        # Username generation settings (compact)
        settings_frame = ttk.LabelFrame(self.root, text="Random Username Settings")
        settings_frame.place(x=pad, y=220, width=770, height=90)

        ttk.Label(settings_frame, text="Length:").place(x=10, y=10)
        self.length_var = tk.IntVar()
        ttk.Entry(settings_frame, textvariable=self.length_var, width=5).place(x=60, y=10)

        self.include_numbers = tk.BooleanVar()
        ttk.Checkbutton(settings_frame, text="Numbers", variable=self.include_numbers).place(x=120, y=10)

        self.include_special = tk.BooleanVar()
        ttk.Checkbutton(settings_frame, text="Special (_ .)", variable=self.include_special).place(x=200, y=10)

        ttk.Label(settings_frame, text="Prefix:").place(x=10, y=40)
        self.prefix_var = tk.StringVar()
        ttk.Entry(settings_frame, textvariable=self.prefix_var, width=10).place(x=60, y=40)

        self.prefix_pos_var = tk.StringVar()
        ttk.Radiobutton(settings_frame, text="Start", variable=self.prefix_pos_var, value="start").place(x=140, y=40)
        ttk.Radiobutton(settings_frame, text="End", variable=self.prefix_pos_var, value="end").place(x=200, y=40)

        # Mode selection
        mode_frame = ttk.LabelFrame(self.root, text="Mode")
        mode_frame.place(x=pad, y=320, width=770, height=50)
        self.mode_var = tk.StringVar()
        ttk.Radiobutton(mode_frame, text="Custom only", variable=self.mode_var, value="custom").place(x=10, y=10)
        ttk.Radiobutton(mode_frame, text="Random only", variable=self.mode_var, value="random").place(x=150, y=10)
        ttk.Radiobutton(mode_frame, text="Both", variable=self.mode_var, value="both").place(x=300, y=10)

        # Thread count input
        thread_frame = ttk.LabelFrame(self.root, text="Threads")
        thread_frame.place(x=pad, y=380, width=770, height=50)
        ttk.Label(thread_frame, text="Threads (per mode):").place(x=10, y=10)
        self.thread_count_var = tk.IntVar()
        self.thread_entry = ttk.Entry(thread_frame, textvariable=self.thread_count_var, width=5)
        self.thread_entry.place(x=140, y=10)

        # Control buttons
        control_frame = ttk.Frame(self.root)
        control_frame.place(x=pad, y=440, width=770, height=40)
        self.start_btn = ttk.Button(control_frame, text="Start", command=self.start_checking)
        self.start_btn.pack(side="left", padx=5)
        self.stop_btn = ttk.Button(control_frame, text="Stop", command=self.stop_checking, state="disabled")
        self.stop_btn.pack(side="left", padx=5)
        ttk.Button(control_frame, text="Clear Log", command=self.clear_log).pack(side="left", padx=5)

        # Log output
        log_frame = ttk.LabelFrame(self.root, text="Log Output")
        log_frame.place(x=pad, y=490, width=770, height=180)
        self.log_text = tk.Text(log_frame, bg="#111", fg="#0f0", font=("Consolas", 10))
        self.log_text.pack(fill="both", expand=True)

    def apply_config_to_widgets(self):
        c = self.config
        self.webhook_random_entry.delete(0, tk.END)
        self.webhook_random_entry.insert(0, c.get("webhook_random", ""))
        self.webhook_custom_entry.delete(0, tk.END)
        self.webhook_custom_entry.insert(0, c.get("webhook_custom", ""))
        self.proxy_text.delete("1.0", tk.END)
        self.proxy_text.insert("1.0", c.get("proxies", ""))
        self.custom_text.delete("1.0", tk.END)
        self.custom_text.insert("1.0", c.get("custom_usernames", ""))
        self.length_var.set(c.get("username_settings", {}).get("length", 6))
        self.include_numbers.set(c.get("username_settings", {}).get("include_numbers", True))
        self.include_special.set(c.get("username_settings", {}).get("include_special", True))
        self.prefix_var.set(c.get("username_settings", {}).get("prefix", ""))
        self.prefix_pos_var.set(c.get("username_settings", {}).get("prefix_pos", "start"))
        self.mode_var.set(c.get("mode", "both"))
        self.thread_count_var.set(c.get("thread_count", 5))

    def save_config(self):
        # Prepare dictionary for saving
        self.config["webhook_random"] = self.webhook_random_entry.get()
        self.config["webhook_custom"] = self.webhook_custom_entry.get()
        self.config["proxies"] = self.proxy_text.get("1.0", tk.END).strip()
        self.config["custom_usernames"] = self.custom_text.get("1.0", tk.END).strip()
        self.config["username_settings"] = {
            "length": self.length_var.get(),
            "include_numbers": self.include_numbers.get(),
            "include_special": self.include_special.get(),
            "prefix": self.prefix_var.get(),
            "prefix_pos": self.prefix_pos_var.get()
        }
        self.config["mode"] = self.mode_var.get()
        self.config["thread_count"] = self.thread_count_var.get()
        try:
            with open(self.config_file, "w") as f:
                yaml.safe_dump(self.config, f)
        except Exception as e:
            self.log(f"[Config Save Error] {e}")

    def load_config(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r") as f:
                    self.config = yaml.safe_load(f) or {}
            except Exception:
                self.config = {}
        else:
            self.config = {}

    def log(self, msg):
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)

    def clear_log(self):
        self.log_text.delete("1.0", tk.END)

    def parse_proxies(self):
        lines = self.proxy_text.get("1.0", tk.END).splitlines()
        proxies = [line.strip() for line in lines if line.strip()]
        return proxies if proxies else None

    def get_random_proxy(self):
        proxies = self.parse_proxies()
        if not proxies:
            return None
        proxy_str = random.choice(proxies)
        proxy_url = f"http://{proxy_str}"
        return {"http": proxy_url, "https": proxy_url}

    def send_webhook(self, url, message):
        if not url:
            return
        try:
            resp = requests.post(url, json={"content": message}, timeout=10)
            if resp.status_code == 429:
                retry_after = resp.json().get("retry_after", 1)
                self.log(f"[Webhook Rate Limit] Sleeping {retry_after}s...")
                time.sleep(retry_after)
                # Retry once
                resp = requests.post(url, json={"content": message}, timeout=10)
            if resp.status_code != 204:
                self.log(f"[Webhook Error] Status {resp.status_code}: {resp.text}")
        except Exception as e:
            self.log(f"[Webhook Error] {e}")

    def generate_username(self):
        length = self.length_var.get()
        charset = list(string.ascii_lowercase)
        if self.include_numbers.get():
            charset += list(string.digits)
        if self.include_special.get():
            charset += ['_', '.']
        prefix = self.prefix_var.get()
        if len(prefix) > length:
            return None
        rand_len = length - len(prefix)
        rand_part = ''.join(random.choices(charset, k=rand_len))
        if self.prefix_pos_var.get() == "start":
            return prefix + rand_part
        else:
            return rand_part + prefix

    def check_username(self, username, webhook_url, is_custom=False):
        # For random usernames, skip if already tried
        if not is_custom:
            with self.lock:
                if username in self.tried_usernames:
                    return
                self.tried_usernames.add(username)

        proxies = self.get_random_proxy()
        try:
            resp = requests.post(
                "https://discord.com/api/v9/unique-username/username-attempt-unauthed",
                json={"username": username},
                proxies=proxies,
                timeout=10,
                verify=False
            )
        except Exception as e:
            self.log(f"[Error] Request failed for {username}: {e}")
            return

        if resp.status_code == 200:
            data = resp.json()
            taken = data.get("taken", True)
            if not taken:
                self.log(f"[AVAILABLE] {username}")
                self.send_webhook(webhook_url, f"Available username: {username}")
            else:
                self.log(f"[TAKEN] {username}")
        elif resp.status_code == 429:
            retry_after = resp.json().get("retry_after", 1)
            self.log(f"[Rate Limit] Sleeping for {retry_after} seconds...")
            time.sleep(retry_after)
            self.check_username(username, webhook_url, is_custom)
        else:
            self.log(f"[Error] Status {resp.status_code} for {username}")

    def worker(self, is_random, webhook_url):
        while not self.stop_event.is_set():
            if is_random:
                username = self.generate_username()
                if username is None:
                    self.log("[Error] Prefix longer than username length")
                    break
                self.check_username(username, webhook_url, is_custom=False)
            else:
                try:
                    username = self.custom_queue.get_nowait()
                except queue.Empty:
                    # No more custom usernames - stop this thread
                    break
                self.check_username(username, webhook_url, is_custom=True)

            time.sleep(0.1)  # slight delay to avoid hammering

    def start_checking(self):
        if self.running:
            return

        mode = self.mode_var.get()
        custom_list = [u.strip() for u in self.custom_text.get("1.0", tk.END).splitlines() if u.strip()]

        # Validate thread count
        try:
            thread_count = self.thread_count_var.get()
            if thread_count < 1:
                raise ValueError
            if thread_count > 50:
                messagebox.showwarning("Warning", "Thread count capped at 50.")
                thread_count = 50
        except Exception:
            messagebox.showerror("Error", "Invalid thread count")
            return

        # Save current config
        self.save_config()

        self.custom_queue = queue.Queue()
        for username in custom_list:
            self.custom_queue.put(username)

        self.running = True
        self.stop_event.clear()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.tried_usernames.clear()
        self.threads.clear()
        self.log("[*] Starting checking...")

        # Start threads
        if mode in ("custom", "both") and not self.custom_queue.empty():
            for _ in range(thread_count):
                t = threading.Thread(target=self.worker, args=(False, self.webhook_custom_entry.get()))
                t.daemon = True
                t.start()
                self.threads.append(t)

        if mode in ("random", "both"):
            for _ in range(thread_count):
                t = threading.Thread(target=self.worker, args=(True, self.webhook_random_entry.get()))
                t.daemon = True
                t.start()
                self.threads.append(t)

        # Monitor threads to enable stop button when done
        threading.Thread(target=self.monitor_threads, daemon=True).start()

    def monitor_threads(self):
        for t in self.threads:
            t.join()
        self.running = False
        self.stop_event.set()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.log("[*] Checking stopped.")

    def stop_checking(self):
        if not self.running:
            return
        self.stop_event.set()
        self.log("[*] Stopping...")
        # Threads will exit soon

def main():
    root = tk.Tk()
    app = DiscordUsernameChecker(root)
    root.mainloop()

if __name__ == "__main__":
    main()
