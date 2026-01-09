import tkinter as tk
from tkinter import ttk

root = tk.Tk()
root.geometry("400x150")

mode_frame = ttk.LabelFrame(root, text="Mode & Thread Count")
mode_frame.place(x=10, y=10, width=380, height=100)

mode_var = tk.StringVar(value="both")
ttk.Radiobutton(mode_frame, text="Custom only", variable=mode_var, value="custom").place(x=10, y=10)
ttk.Radiobutton(mode_frame, text="Random only", variable=mode_var, value="random").place(x=150, y=10)
ttk.Radiobutton(mode_frame, text="Both", variable=mode_var, value="both").place(x=300, y=10)

ttk.Label(mode_frame, text="Custom Threads:").place(x=10, y=50)
custom_threads = tk.IntVar(value=2)
ttk.Entry(mode_frame, textvariable=custom_threads, width=5).place(x=120, y=50)

ttk.Label(mode_frame, text="Random Threads:").place(x=200, y=50)
random_threads = tk.IntVar(value=2)
ttk.Entry(mode_frame, textvariable=random_threads, width=5).place(x=320, y=50)

root.mainloop()
