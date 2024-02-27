import os
import csv
import datetime
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
import threading
import time
import psutil
import sqlite3

# Function to initialize the database and table
def initialize_database():
    conn = sqlite3.connect("malware_signatures.db")
    cursor = conn.cursor()

    # Create a table to store malware signatures
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS malware_signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            signature TEXT UNIQUE
        )
    ''')

    # Insert sample signatures into the table
    sample_signatures = ["malware_process1.exe", "malware_process2.exe"]
    for signature in sample_signatures:
        cursor.execute("INSERT OR IGNORE INTO malware_signatures (signature) VALUES (?)", (signature,))

    conn.commit()
    conn.close()

# Function to fetch malware signatures from the database
def fetch_malware_signatures():
    conn = sqlite3.connect("malware_signatures.db")
    cursor = conn.cursor()

    cursor.execute("SELECT signature FROM malware_signatures")
    signatures = [row[0] for row in cursor.fetchall()]

    conn.close()
    return signatures

# Function to add a new malware signature to the database
def add_malware_signature():
    signature = simpledialog.askstring("Add Malware Signature", "Enter malware signature:")
    if signature:
        try:
            conn = sqlite3.connect("malware_signatures.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO malware_signatures (signature) VALUES (?)", (signature,))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", f"Malware signature '{signature}' added successfully.")
        except sqlite3.IntegrityError:
            messagebox.showwarning("Warning", f"Malware signature '{signature}' already exists.")

# Function to remove a malware signature from the database
def remove_malware_signature():
    signatures = fetch_malware_signatures()
    if not signatures:
        messagebox.showinfo("Info", "No malware signatures found in the database.")
        return

    selected_signature = simpledialog.askitemlist("Remove Malware Signature", "Select malware signature:", items=signatures)
    if selected_signature:
        try:
            conn = sqlite3.connect("malware_signatures.db")
            cursor = conn.cursor()
            cursor.execute("DELETE FROM malware_signatures WHERE signature = ?", (selected_signature,))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", f"Malware signature '{selected_signature}' removed successfully.")
        except sqlite3.Error as e:
            messagebox.showerror("Error", f"Error removing malware signature: {e}")

# Function to log process information to a CSV file
def log_to_file(message):
    with open("process_monitor_log.csv", "a", newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(message)

# Class definition for the GUI
class ProcessMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Process Monitor")

        # Initialize the database
        initialize_database()

        # Fetch malware signatures from the database
        self.malware_signatures = fetch_malware_signatures()

        self.text_area = scrolledtext.ScrolledText(root, width=80, height=20)
        self.text_area.pack(padx=10, pady=10)

        self.start_button = tk.Button(root, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(root, text="Stop Monitoring", command=self.stop_monitoring)
        self.stop_button.pack(pady=5)

        self.config_button = tk.Button(root, text="Configure Malware Signatures", command=self.configure_malware_signatures)
        self.config_button.pack(pady=5)

        self.monitoring_thread = None
        self.running = False

    def start_monitoring(self):
        if not self.running:
            self.running = True
            self.monitoring_thread = threading.Thread(target=self.monitor)
            self.monitoring_thread.start()

    def is_malware(self, process_name):
        return any(signature in process_name.lower() for signature in self.malware_signatures)

    def monitor(self):
        while self.running:
            try:
                for process in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'create_time', 'ppid']):
                    try:
                        proc_owner = process.info['username']
                        create_date = datetime.datetime.fromtimestamp(process.info['create_time']).strftime('%Y-%m-%d %H:%M:%S')
                        executable = os.path.basename(process.info['name'])
                        cmdline = ' '.join(process.info['cmdline'])
                        pid = process.info['pid']
                        parent_pid = process.info['ppid']
                        privileges = "N/A"

                        if self.is_malware(executable):
                            print(f"Potential malware detected: {executable}")

                        process_log_message = [
                            create_date,
                            proc_owner,
                            executable,
                            cmdline,
                            pid,
                            parent_pid,
                            privileges
                        ]

                        log_to_file(process_log_message)
                        self.text_area.insert(tk.END, f"{process_log_message}\n")
                        self.text_area.yview(tk.END)

                    except Exception as e:
                        print(f"Error processing individual process: {e}")

            except Exception as e:
                print(f"Error in monitoring thread: {e}")

            time.sleep(1)  # Adjust the interval as needed

    def stop_monitoring(self):
        if self.running:
            self.running = False
            self.monitoring_thread.join()

    def configure_malware_signatures(self):
        config_window = tk.Toplevel(self.root)
        config_window.title("Malware Signature Configuration")

        add_button = tk.Button(config_window, text="Add Malware Signature", command=add_malware_signature)
        add_button.pack(pady=5)

        remove_button = tk.Button(config_window, text="Remove Malware Signature", command=remove_malware_signature)
        remove_button.pack(pady=5)

if __name__ == "__main__":
    root = tk.Tk()
    app = ProcessMonitorGUI(root)
    root.mainloop()