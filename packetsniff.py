from tkinter import *
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP
import threading
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from collections import Counter

BLOCK_RULES = []
packet_counter = Counter()
src_ip_counter=Counter()
dst_ip_counter=Counter()
dst_port_counter=Counter()

def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if TCP in packet:
            protocol = "TCP"
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            dst_port = packet[UDP].dport
        else:
            protocol = "Other"
            dst_port = "N/A"
        packet_counter[protocol] += 1
        src_ip_counter[src_ip] += 1
        dst_ip_counter[dst_ip] += 1
        dst_port_counter[dst_port] += 1
        for rule in BLOCK_RULES:
            if rule.get("src_ip") and rule["src_ip"] != src_ip:
                continue
            if rule.get("dst_ip") and rule["dst_ip"] != dst_ip:
                continue
            if rule.get("protocol") and rule["protocol"] != protocol.lower():
                continue
            if rule.get("dst_port") and rule["dst_port"] != dst_port:
                continue
            log_label.config(text=f"Dropped packet from {src_ip} to {dst_ip} (Protocol: {protocol}, Port: {dst_port})")
            return
        tree.insert("", "end", values=(src_ip, dst_ip, protocol, dst_port))
        
def start_sniffing(interface):
    sniff(iface=interface, prn=process_packet, filter="ip", store=0)

def start_sniffing_thread():
    interface = interface_entry.get().strip()
    if not interface:
        log_label.config(text="Please enter a network interface!")
        return
    log_label.config(text=f"Monitoring on interface: {interface}")
    sniff_thread = threading.Thread(target=start_sniffing, args=(interface,))
    sniff_thread.daemon = True
    sniff_thread.start()
def add_block_rule():
    protocol = protocol_entry.get().strip().lower()
    src_ip = src_ip_entry.get().strip()
    dst_ip = dst_ip_entry.get().strip()
    dst_port = dst_port_entry.get().strip()
    if protocol and protocol not in ["tcp", "udp"]:
        log_label.config(text="Invalid protocol used in the block rule. Use 'TCP'or 'UDP'.")
        return
    try:
        dst_port = int(dst_port) if dst_port else None
    except ValueError:
        log_label.config(text="Invalid destination port. Use a numeric value.")
        return
    rule = {}
    if protocol:
        rule["protocol"] = protocol
    if src_ip:
        rule["src_ip"] = src_ip
    if dst_ip:
        rule["dst_ip"] = dst_ip
    if dst_port:
        rule["dst_port"] = dst_port
    BLOCK_RULES.append(rule)
    log_label.config(text=f"Added block rule: {rule}")
    update_rules_display()
def update_rules_display():
    rules_list.delete(0, END)
    for rule in BLOCK_RULES:
        rules_list.insert(END, str(rule))
def update_graph():
    global scheduled_task
    selected_view = graph_option.get()
    if selected_view == "Packets by Protocol":
        data = packet_counter
        xlabel = "Protocol"
    elif selected_view == "Packets by Source IP":
        data = src_ip_counter
        xlabel = "Source IP"
    elif selected_view == "Packets by Destination IP":
        data = dst_ip_counter
        xlabel = "Destination IP"
    elif selected_view == "Packets by Destination Port":
        data = dst_port_counter
        xlabel = "Destination Port"
    ax.clear() 
    
    labels, values = zip(*data.most_common(10)) if data else ([], [])
    x_positions = range(len(labels))
    ax.bar(x_positions, values, color="skyblue")
    ax.set_xticks(x_positions)
    ax.set_xticklabels(labels)
    
    
    ax.set_title(selected_view)
    ax.set_xlabel(xlabel)
    ax.set_ylabel("Count")
    canvas.draw()
    root.after(1000, update_graph)
root = Tk()
root.title("Dynamic Packet Monitoring & Firewall")
root.geometry("1980x1080")
root.iconbitmap("icon.ico")
frame = Frame(root)
frame.pack(pady=10)
Label(frame, text="Network Interface:").pack(side=LEFT, padx=5)
interface_entry = Entry(frame, width=30)
interface_entry.pack(side=LEFT, padx=5)
start_button = Button(frame, text="Start Monitoring", command=start_sniffing_thread)
start_button.pack(side=LEFT, padx=5)

log_label = Label(root, text="", fg="blue")
log_label.pack()
columns = ("Source IP", "Destination IP", "Protocol", "Destination Port")
tree = ttk.Treeview(root, columns=columns, show="headings", height=10)
tree.pack(fill=BOTH, expand=True, pady=10)
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=150)
block_frame = Frame(root)
block_frame.pack(pady=10, fill=X)

Label(block_frame, text="Protocol:").grid(row=0, column=0, padx=5, pady=5)
protocol_entry = Entry(block_frame, width=10)
protocol_entry.grid(row=0, column=1, padx=5, pady=5)

Label(block_frame, text="Source IP:").grid(row=0, column=2, padx=5, pady=5)
src_ip_entry = Entry(block_frame, width=15)
src_ip_entry.grid(row=0, column=3, padx=5, pady=5)

Label(block_frame, text="Destination IP:").grid(row=0, column=4, padx=5, pady=5)
dst_ip_entry = Entry(block_frame, width=15)
dst_ip_entry.grid(row=0, column=5, padx=5, pady=5)

Label(block_frame, text="Destination Port:").grid(row=0, column=6, padx=5, pady=5)
dst_port_entry = Entry(block_frame, width=10)
dst_port_entry.grid(row=0, column=7, padx=5, pady=5)

add_rule_button = Button(block_frame, text="Add Block Rule", command=add_block_rule)
add_rule_button.grid(row=0, column=8, padx=10, pady=5)
rules_list = Listbox(root, height=5)
rules_list.pack(fill=X, pady=10)

graph_frame = Frame(root)
graph_frame.pack(pady=10)

Label(graph_frame, text="Select Graph View:").pack(side=LEFT, padx=5)
graph_option = StringVar(value="Packets by Protocol")

graph_menu = ttk.Combobox(graph_frame, textvariable=graph_option, values=[
    "Packets by Protocol", "Packets by Source IP", "Packets by Destination IP","Packets by Destination Port"
], state="readonly", width=25)
clear_button = Button(
    frame,
    text="Clear Logs",
    command=lambda: clear_logs()
)
clear_button.pack(side=LEFT, padx=5)

def clear_logs():
    # Clear the Treeview (log table)
    for item in tree.get_children():
        tree.delete(item)
    
    # Reset all counters
    packet_counter.clear()
    src_ip_counter.clear()
    dst_ip_counter.clear()
    dst_port_counter.clear()
    
    # Clear the rules list display
    rules_list.delete(0, END)
    
    # Reset the log label
    log_label.config(text="Logs cleared. Monitoring continues.")

graph_menu.pack(side=LEFT, padx=5)
fig, ax = plt.subplots(figsize=(5, 3))
canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().pack(side=RIGHT, fill=BOTH, expand=True)
update_graph()
root.mainloop()