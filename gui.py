import tkinter as tk
from tkinter import scrolledtext
import threading
from packet_sniffer import start_sniffing
from logger import log_to_file

def start_capture():
    output_text.insert(tk.END, "\n[+] Starting packet capture...\n")
    thread = threading.Thread(target=start_sniffing, args=("eth0", update_output))
    thread.daemon = True
    thread.start()

def update_output(packet_info):
    if packet_info:
        output_text.insert(tk.END, packet_info + "\n")
        output_text.yview(tk.END)
        log_to_file(packet_info)

def start_gui():
    global output_text
    root = tk.Tk()
    root.title("Network Traffic Analyzer")

    frame = tk.Frame(root)
    frame.pack(pady=10)

    start_button = tk.Button(frame, text="Start Sniffing", command=start_capture)
    start_button.pack()

    output_text = scrolledtext.ScrolledText(root, width=80, height=20)
    output_text.pack()

    root.mainloop()