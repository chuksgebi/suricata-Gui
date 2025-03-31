import json
import tkinter as tk
from tkinter import ttk, messagebox
import threading
from collections import Counter
import time
from datetime import datetime
from PIL import ImageGrab  # For screenshot functionality

# Function to sort columns
def sort_column(tree, col, reverse):
    items = [(tree.set(k, col), k) for k in tree.get_children("")]
    items.sort(reverse=reverse)
    for index, (val, k) in enumerate(items):
        tree.move(k, "", index)
    tree.heading(col, command=lambda: sort_column(tree, col, not reverse))

# Anomaly detection function
def detect_anomalies(event, stats):
    event_type = event["event_type"]
    src_ip = event.get("src_ip", "N/A")
    if stats["event_types"].get(event_type, 0) < 5:
        return f"Rare Event Type: {event_type}"
    if stats["src_ips"].get(src_ip, 0) > 50:
        return f"High Activity from IP: {src_ip}"
    if "alert" in event and event["alert"].get("severity", 0) >= 3:
        return f"High Severity Alert: {event['alert'].get('signature', 'N/A')}"
    return None

# Show full event details in a popup
def show_event_details(event):
    details_window = tk.Toplevel(root)
    details_window.title("Event Details")
    details_window.geometry("400x300")
    text = tk.Text(details_window, wrap="word")
    text.pack(fill="both", expand=True, padx=10, pady=10)
    text.insert("end", json.dumps(event, indent=2))
    text.config(state="disabled")
    ttk.Button(details_window, text="Close", command=details_window.destroy).pack(pady=5)

# Filter and display events
def filter_events(tree, filter_entry, date_entry, section_var, stats, event_store):
    search = filter_entry.get().lower()
    date_filter = date_entry.get().strip()
    section = section_var.get()
    for item in tree.get_children():
        tree.delete(item)
    
    event_count = 0
    try:
        with open("/var/log/suricata/eve.json", "r") as f:
            for line in f:
                try:
                    event = json.loads(line)
                    timestamp = event["timestamp"]
                    if date_filter:
                        event_date = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z").date()
                        filter_date = datetime.strptime(date_filter, "%Y-%m-%d").date()
                        if event_date != filter_date:
                            continue
                    
                    anomaly = detect_anomalies(event, stats)
                    display_values = None
                    if section == "All Events" and (not search or search in event["event_type"].lower()):
                        display_values = (event_count, event["timestamp"], event["event_type"], event.get("src_ip", "N/A"), event.get("dest_ip", "N/A"))
                    elif section == "Alerts" and "alert" in event and (not search or search in event["alert"].get("signature", "").lower()):
                        display_values = (event_count, event["timestamp"], event["event_type"], event.get("src_ip", "N/A"), event["alert"].get("signature", "N/A"))
                    elif section == "DNS" and event["event_type"] == "dns" and (not search or search in event["dns"].get("rrname", "").lower()):
                        display_values = (event_count, event["timestamp"], "DNS", event.get("src_ip", "N/A"), event["dns"].get("rrname", "N/A"))
                    elif section == "HTTP" and event["event_type"] == "http" and (not search or search in event["http"].get("hostname", "").lower()):
                        display_values = (event_count, event["timestamp"], "HTTP", event.get("src_ip", "N/A"), event["http"].get("hostname", "N/A"))
                    elif section == "Anomalies" and anomaly and (not search or search in anomaly.lower()):
                        display_values = (event_count, event["timestamp"], event["event_type"], event.get("src_ip", "N/A"), anomaly)
                    
                    if display_values:
                        event_count += 1
                        iid = tree.insert("", "end", values=display_values)
                        event_store[iid] = event
                except (json.JSONDecodeError, ValueError):
                    continue
    except FileNotFoundError:
        messagebox.showerror("Error", "Could not find /var/log/suricata/eve.json")

# Real-time file watcher
def watch_file(tree, filter_entry, date_entry, section_var, watch_active, stats, event_store):
    try:
        with open("/var/log/suricata/eve.json", "r") as f:
            f.seek(0, 2)
            event_count = len(tree.get_children())
            while watch_active.get():
                line = f.readline()
                if line:
                    try:
                        event = json.loads(line)
                        timestamp = event["timestamp"]
                        date_filter = date_entry.get().strip()
                        if date_filter:
                            event_date = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z").date()
                            filter_date = datetime.strptime(date_filter, "%Y-%m-%d").date()
                            if event_date != filter_date:
                                continue
                        
                        anomaly = detect_anomalies(event, stats)
                        search = filter_entry.get().lower()
                        section = section_var.get()
                        display_values = None
                        if section == "All Events" and (not search or search in event["event_type"].lower()):
                            display_values = (event_count, event["timestamp"], event["event_type"], event.get("src_ip", "N/A"), event.get("dest_ip", "N/A"))
                        elif section == "Alerts" and "alert" in event and (not search or search in event["alert"].get("signature", "").lower()):
                            display_values = (event_count, event["timestamp"], event["event_type"], event.get("src_ip", "N/A"), event["alert"].get("signature", "N/A"))
                        elif section == "DNS" and event["event_type"] == "dns" and (not search or search in event["dns"].get("rrname", "").lower()):
                            display_values = (event_count, event["timestamp"], "DNS", event.get("src_ip", "N/A"), event["dns"].get("rrname", "N/A"))
                        elif section == "HTTP" and event["event_type"] == "http" and (not search or search in event["http"].get("hostname", "").lower()):
                            display_values = (event_count, event["timestamp"], "HTTP", event.get("src_ip", "N/A"), event["http"].get("hostname", "N/A"))
                        elif section == "Anomalies" and anomaly and (not search or search in anomaly.lower()):
                            display_values = (event_count, event["timestamp"], event["event_type"], event.get("src_ip", "N/A"), anomaly)
                        
                        if display_values:
                            event_count += 1
                            iid = tree.insert("", "end", values=display_values)
                            event_store[iid] = event
                            stats["event_types"][event["event_type"]] += 1
                            stats["src_ips"][event.get("src_ip", "N/A")] += 1
                    except (json.JSONDecodeError, ValueError):
                        continue
                else:
                    time.sleep(0.1)
    except FileNotFoundError:
        messagebox.showerror("Error", "Could not find /var/log/suricata/eve.json")

# Screenshot function for the event page
def take_screenshot():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    x = root.winfo_rootx()
    y = root.winfo_rooty()
    width = root.winfo_width()
    height = root.winfo_height()
    screenshot = ImageGrab.grab(bbox=(x, y, x + width, y + height))
    screenshot.save(f"event_log_{timestamp}.png")
    messagebox.showinfo("Success", f"Screenshot saved as event_log_{timestamp}.png")

# Create the main window
root = tk.Tk()
root.title("Eve.json Viewer")
root.geometry("1000x600")
root.configure(bg="#2b2b2b")
style = ttk.Style()
style.theme_use("clam")

# Filter frame
filter_frame = ttk.Frame(root, relief="raised", borderwidth=2)
filter_frame.pack(fill="x", padx=10, pady=5)
ttk.Label(filter_frame, text="Section:", background="#3c3f41", foreground="white").pack(side="left", padx=5)
section_var = tk.StringVar(value="All Events")
sections = ["All Events", "Alerts", "DNS", "HTTP", "Anomalies"]
ttk.Combobox(filter_frame, textvariable=section_var, values=sections, state="readonly").pack(side="left", padx=5)
ttk.Label(filter_frame, text="Filter:", background="#3c3f41", foreground="white").pack(side="left", padx=5)
filter_entry = ttk.Entry(filter_frame)
filter_entry.pack(side="left", padx=5)
ttk.Label(filter_frame, text="Date (YYYY-MM-DD):", background="#3c3f41", foreground="white").pack(side="left", padx=5)
date_entry = ttk.Entry(filter_frame, width=12)
date_entry.pack(side="left", padx=5)
watch_active = tk.BooleanVar(value=True)
ttk.Checkbutton(filter_frame, text="Real-Time Updates", variable=watch_active).pack(side="left", padx=5)
ttk.Button(filter_frame, text="Apply Filter", command=lambda: filter_events(tree, filter_entry, date_entry, section_var, stats, event_store)).pack(side="left", padx=5)
ttk.Button(filter_frame, text="Take Screenshot", command=take_screenshot).pack(side="left", padx=5)

# Frame for the table
frame = ttk.Frame(root, relief="sunken", borderwidth=2)
frame.pack(fill="both", expand=True, padx=10, pady=5)

# Treeview widget
tree = ttk.Treeview(frame, columns=("Number", "Timestamp", "Event Type", "Source IP", "Details"), show="headings")
tree.heading("Number", text="#", command=lambda: sort_column(tree, "Number", False))
tree.heading("Timestamp", text="Timestamp", command=lambda: sort_column(tree, "Timestamp", False))
tree.heading("Event Type", text="Event Type", command=lambda: sort_column(tree, "Event Type", False))
tree.heading("Source IP", text="Source IP", command=lambda: sort_column(tree, "Source IP", False))
tree.heading("Details", text="Details", command=lambda: sort_column(tree, "Details", False))
tree.column("Number", width=50)
tree.column("Timestamp", width=200)
tree.column("Event Type", width=100)
tree.column("Source IP", width=150)
tree.column("Details", width=350)
scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
tree.configure(yscrollcommand=scrollbar.set)
tree.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")
tree.bind("<Double-1>", lambda e: show_event_details(event_store.get(tree.focus(), {})))

# Initialize stats and event store
stats = {"event_types": Counter(), "src_ips": Counter()}
event_store = {}

# Load initial data
try:
    with open("/var/log/suricata/eve.json", "r") as f:
        event_count = 0
        for line in f:
            try:
                event = json.loads(line)
                stats["event_types"][event["event_type"]] += 1
                stats["src_ips"][event.get("src_ip", "N/A")] += 1
                event_count += 1
                iid = tree.insert("", "end", values=(
                    event_count,
                    event["timestamp"],
                    event["event_type"],
                    event.get("src_ip", "N/A"),
                    event.get("dest_ip", "N/A")
                ))
                event_store[iid] = event
            except json.JSONDecodeError:
                continue
except FileNotFoundError:
    messagebox.showerror("Error", "Could not find /var/log/suricata/eve.json")
    root.destroy()
    exit()

# Start real-time thread
threading.Thread(target=watch_file, args=(tree, filter_entry, date_entry, section_var, watch_active, stats, event_store), daemon=True).start()

# Start the GUI
root.mainloop()
