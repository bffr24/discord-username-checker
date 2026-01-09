import tkinter as tk
from tkinter import ttk, messagebox, filedialog

class UsernameCheckerUIOnly:
    def __init__(self, root):
        self.root = root
        self.root.title("Discord Username Checker (UI Only)")
        self.root.geometry("850x680")
        self.root.resizable(False, False)
        self.style = ttk.Style()
        self.style.theme_use('clam')

        self.create_widgets()

    def create_widgets(self):
        pad = 10

        webhook_frame = ttk.LabelFrame(self.root, text="Discord Webhook")
        webhook_frame.place(x=pad, y=pad, width=820, height=70)
        self.webhook_entry = ttk.Entry(webhook_frame)
        self.webhook_entry.place(x=10, y=10, width=790, height=25)
        self.webhook_entry.insert(0, "https://discord.com/api/webhooks/your_webhook_here")

        proxy_frame = ttk.LabelFrame(self.root, text="Proxies (one per line) [username:password@ip:port or ip:port]")
        proxy_frame.place(x=pad, y=90, width=400, height=150)
        self.proxy_text = tk.Text(proxy_frame, height=7, width=47)
        self.proxy_text.pack(padx=5, pady=5)

        specified_frame = ttk.LabelFrame(self.root, text="Specified Usernames to Always Check (one per line)")
        specified_frame.place(x=430, y=90, width=400, height=150)
        self.specified_text = tk.Text(specified_frame, height=7, width=47)
        self.specified_text.pack(padx=5, pady=5)

        settings_frame = ttk.LabelFrame(self.root, text="Username Generation Settings")
        settings_frame.place(x=pad, y=250, width=820, height=140)
        ttk.Label(settings_frame, text="Username Length (without prefix):").place(x=10, y=10)
        self.username_length_var = tk.StringVar(value="6")
        self.username_length_entry = ttk.Entry(settings_frame, textvariable=self.username_length_var, width=5)
        self.username_length_entry.place(x=220, y=10)

        ttk.Label(settings_frame, text="Include Numbers:").place(x=280, y=10)
        self.include_numbers_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, variable=self.include_numbers_var).place(x=380, y=10)

        ttk.Label(settings_frame, text="Include Special Characters (_ and .):").place(x=420, y=10)
        self.include_special_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, variable=self.include_special_var).place(x=680, y=10)

        ttk.Label(settings_frame, text="Prefix (optional):").place(x=10, y=50)
        self.prefix_var = tk.StringVar()
        self.prefix_entry = ttk.Entry(settings_frame, textvariable=self.prefix_var, width=15)
        self.prefix_entry.place(x=120, y=50)

        ttk.Label(settings_frame, text="Prefix position:").place(x=300, y=50)
        self.prefix_pos_var = tk.StringVar(value="start")
        ttk.Radiobutton(settings_frame, text="Start", variable=self.prefix_pos_var, value="start").place(x=410, y=50)
        ttk.Radiobutton(settings_frame, text="End", variable=self.prefix_pos_var, value="end").place(x=480, y=50)

        control_frame = ttk.Frame(self.root)
        control_frame.place(x=pad, y=400, width=820, height=40)
        self.start_button = ttk.Button(control_frame, text="Start", command=self.dummy_action)
        self.start_button.pack(side="left", padx=5)
        self.stop_button = ttk.Button(control_frame, text="Stop", command=self.dummy_action)
        self.stop_button.pack(side="left", padx=5)
        self.clear_log_button = ttk.Button(control_frame, text="Clear Log", command=self.clear_log)
        self.clear_log_button.pack(side="left", padx=5)

        log_frame = ttk.LabelFrame(self.root, text="Log / Output")
        log_frame.place(x=pad, y=450, width=820, height=210)
        self.log_text = tk.Text(log_frame, state="normal", bg="#111", fg="#0f0", font=("Consolas", 10))
        self.log_text.pack(fill="both", expand=True)

    def dummy_action(self):
        self.log("This is a UI-only version. No logic is implemented.")

    def log(self, msg):
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)

    def clear_log(self):
        self.log_text.delete("1.0", tk.END)


def main():
    root = tk.Tk()
    app = UsernameCheckerUIOnly(root)
    root.mainloop()

if __name__ == "__main__":
    main()
