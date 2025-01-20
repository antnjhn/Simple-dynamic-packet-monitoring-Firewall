from tkinter import *
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP
import threading
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from collections import Counter

# Initialize block rules and packet counters
BLOCK_RULES = []
packet_counter = Counter()  # For counting packets by protocol
src_ip_counter = Counter()  # For counting packets by source IP
dst_ip_counter = Counter()  # For counting packets by destination IP
scheduled_task = None       # Variable to store the scheduled task reference

# Function to process and display packet details
def process_packet(packet):
    if IP in packet:
        # Extract packet details
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"

        # Update counters
        packet_counter[protocol] += 1
        src_ip_counter[src_ip] += 1
        dst_ip_counter[dst_ip] += 1

        # Check if the packet matches any block rule
        for rule in BLOCK_RULES:
            if rule.get("src_ip") and rule["src_ip"] != src_ip:
                continue
            if rule.get("dst_ip") and rule["dst_ip"] != dst_ip:
                continue
            if rule.get("protocol") and rule["protocol"] != protocol.lower():
                continue
            # Packet matches a block rule, drop it
            log_label.config(text=f"Dropped packet from {src_ip} to {dst_ip} (Protocol: {protocol})")
            return

        # If no block rule matches, display the packet
        tree.insert("", "end", values=(src_ip, dst_ip, protocol))

# Function to update the graph based on the selected view
def update_graph():
    global scheduled_task
    selected_view = graph_option.get()  # Get the selected graph type

    # Prepare data based on the selected view
    if selected_view == "Packets by Protocol":
        data = packet_counter
        xlabel = "Protocol"
    elif selected_view == "Packets by Source IP":
        data = src_ip_counter
        xlabel = "Source IP"
    elif selected_view == "Packets by Destination IP":
        data = dst_ip_counter
        xlabel = "Destination IP"

    # Update the graph
    ax.clear()
    labels, values = zip(*data.most_common(10)) if data else ([], [])  # Limit to top 10 entries
    ax.bar(labels, values, color="skyblue")
    ax.set_title(selected_view)
    ax.set_xlabel(xlabel)
    ax.set_ylabel("Count")
    canvas.draw()

    # Schedule the next update
    scheduled_task = root.after(1000, update_graph)

# Function to handle window close
def on_close():
    global scheduled_task
    if scheduled_task:
        root.after_cancel(scheduled_task)  # Cancel the scheduled task
    root.destroy()  # Destroy the Tkinter window

# Initialize the main GUI window
root = Tk()
root.title("Network Packet Monitor with Graph Switching")
root.geometry("1200x600")

# Frame for interface input
frame = Frame(root)
frame.pack(pady=10)

Label(frame, text="Network Interface:").pack(side=LEFT, padx=5)
interface_entry = Entry(frame, width=20)
interface_entry.pack(side=LEFT, padx=5)
start_button = Button(frame, text="Start Monitoring", command=lambda: threading.Thread(target=sniff, args=(interface_entry.get(),)).start())
start_button.pack(side=LEFT, padx=5)

log_label = Label(root, text="", fg="blue")
log_label.pack()

# Packet display table
columns = ("Source IP", "Destination IP", "Protocol")
tree = ttk.Treeview(root, columns=columns, show="headings", height=10)
tree.pack(fill=BOTH, expand=True, pady=10)

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=150)

# Dropdown menu for graph options
graph_frame = Frame(root)
graph_frame.pack(pady=10)

Label(graph_frame, text="Select Graph View:").pack(side=LEFT, padx=5)
graph_option = StringVar(value="Packets by Protocol")
graph_menu = ttk.Combobox(graph_frame, textvariable=graph_option, values=[
    "Packets by Protocol", "Packets by Source IP", "Packets by Destination IP"
], state="readonly", width=25)
graph_menu.pack(side=LEFT, padx=5)

# Graph for packet statistics
fig, ax = plt.subplots(figsize=(6, 4))
canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().pack(side=RIGHT, fill=BOTH, expand=True)

# Start the graph update loop
update_graph()

# Bind the close event to the custom handler
root.protocol("WM_DELETE_WINDOW", on_close)

# Run the GUI
root.mainloop()
