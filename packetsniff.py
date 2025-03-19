from tkinter import *
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether
import threading, time, os
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from collections import Counter, defaultdict, deque
BLOCK_RULES = []
packet_counter = Counter()
src_ip_counter = Counter()
dst_ip_counter = Counter()
dst_port_counter = Counter()
protocol_details = {}
src_ip_details = {}
dst_ip_details = {}
dst_port_details = {}
stop_event = threading.Event()

src_mac_counter = Counter()
dst_mac_counter = Counter()

# UDP attack detection globals
udp_packets = defaultdict(deque)
udp_threshold = 100  
TIME_WINDOW = 1      
blocked_ips = set()

start_time = None

def update_details(protocol, src_ip, dst_ip, dst_port):
    key = protocol.lower()
    if key not in protocol_details:
        protocol_details[key] = {"src_ip": Counter(), "dst_ip": Counter(), "dst_port": Counter()}
    protocol_details[key]["src_ip"][src_ip] += 1
    protocol_details[key]["dst_ip"][dst_ip] += 1
    protocol_details[key]["dst_port"][dst_port] += 1

    if src_ip not in src_ip_details:
        src_ip_details[src_ip] = {"protocol": Counter(), "dst_ip": Counter(), "dst_port": Counter()}
    src_ip_details[src_ip]["protocol"][protocol.lower()] += 1
    src_ip_details[src_ip]["dst_ip"][dst_ip] += 1
    src_ip_details[src_ip]["dst_port"][dst_port] += 1

    if dst_ip not in dst_ip_details:
        dst_ip_details[dst_ip] = {"protocol": Counter(), "src_ip": Counter(), "dst_port": Counter()}
    dst_ip_details[dst_ip]["protocol"][protocol.lower()] += 1
    dst_ip_details[dst_ip]["src_ip"][src_ip] += 1
    dst_ip_details[dst_ip]["dst_port"][dst_port] += 1

    if dst_port not in dst_port_details:
        dst_port_details[dst_port] = {"protocol": Counter(), "src_ip": Counter(), "dst_ip": Counter()}
    dst_port_details[dst_port]["protocol"][protocol.lower()] += 1
    dst_port_details[dst_port]["src_ip"][src_ip] += 1
    dst_port_details[dst_port]["dst_ip"][dst_ip] += 1

def show_udp_attack_popup(src_ip):
    popup = Toplevel(root)
    popup.title("UDP Attack Detected")
    Label(popup, text=f"UDP attack detected from {src_ip}!", fg="red", font=("Arial", 14, "bold")).pack(padx=20, pady=20)
    Button(popup, text="OK", command=popup.destroy).pack(pady=10)

def block_ip(src_ip):
    """
    Block traffic from src_ip by adding it to the blocked_ips set,
    update the GUI list, and issue an iptables command (Linux).
    """
    if src_ip not in blocked_ips:
        blocked_ips.add(src_ip)
        update_blocked_list()
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        log_label.config(text=f"Blocked IP: {src_ip}")

def update_blocked_list():
    blocked_list.delete(0, END)
    for ip in sorted(blocked_ips):
        blocked_list.insert(END, ip)

def process_packet(packet):
    
    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        src_mac_counter[src_mac] += 1
        dst_mac_counter[dst_mac] += 1

    # Process IP packets
    if IP in packet:
        src_ip = packet[IP].src
        
        if src_ip in blocked_ips:
            return
        dst_ip = packet[IP].dst
        if TCP in packet:
            protocol = "TCP"
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            dst_port = packet[UDP].dport
            # --- UDP Attack Detection Logic ---
            current_time = time.time()
            udp_packets[src_ip].append(current_time)
            while udp_packets[src_ip] and current_time - udp_packets[src_ip][0] > TIME_WINDOW:
                udp_packets[src_ip].popleft()
            if len(udp_packets[src_ip]) > udp_threshold:
                show_udp_attack_popup(src_ip)
                rule = {"protocol": "udp", "src_ip": src_ip}
                if rule not in BLOCK_RULES:
                    BLOCK_RULES.append(rule)
                    update_rules_display()
                block_ip(src_ip)
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            dst_port = "N/A"
        else:
            protocol = "Other"
            dst_port = "N/A"
        
        packet_counter[protocol] += 1
        src_ip_counter[src_ip] += 1
        dst_ip_counter[dst_ip] += 1
        dst_port_counter[dst_port] += 1
        update_details(protocol, src_ip, dst_ip, dst_port)
        
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
    def packet_handler(packet):
        if stop_event.is_set():
            return True
        process_packet(packet)
    sniff(iface=interface, prn=packet_handler, filter="ip", store=0)

def start_sniffing_thread():
    global start_time
    interface = "Wi-Fi" 
    if stop_event.is_set():
        log_label.config(text="Monitoring is already stopped. Restart monitoring.")
        return
    start_time = time.time()  
    log_label.config(text=f"Monitoring on interface: {interface}")
    threading.Thread(target=start_sniffing, args=(interface,), daemon=True).start()
    update_elapsed_time()

def stop_sniffing():
    stop_event.set()
    log_label.config(text="Monitoring stopped.")

def add_block_rule():
    protocol = protocol_entry.get().strip().lower()
    src_ip = src_ip_entry.get().strip()
    dst_ip = dst_ip_entry.get().strip()
    dst_port = dst_port_entry.get().strip()
    
    if protocol and protocol not in ["tcp", "udp"]:
        log_label.config(text="Invalid protocol. Use 'TCP' or 'UDP'.")
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

def clear_logs():
    for item in tree.get_children():
        tree.delete(item)
    packet_counter.clear()
    src_ip_counter.clear()
    dst_ip_counter.clear()
    dst_port_counter.clear()
    rules_list.delete(0, END)
    log_label.config(text="Logs cleared. Monitoring continues.")

def update_elapsed_time():
    if start_time is not None and not stop_event.is_set():
        elapsed = time.time() - start_time
        elapsed_time_label.config(text=f"Elapsed Time: {elapsed:.1f} sec")
        root.after(1000, update_elapsed_time)

tooltip_window = None
last_bar_index = -1

def on_hover(event):
    global tooltip_window, last_bar_index
    if not hasattr(event, 'inaxes') or event.inaxes != ax:
        if tooltip_window:
            tooltip_window.destroy()
            tooltip_window = None
        last_bar_index = -1
        return
    
    current_bar_index = -1
    for i, rect in enumerate(bars):
        if i >= len(labels):
            continue
        contains, _ = rect.contains(event)
        if contains:
            current_bar_index = i
            break
    
    if current_bar_index != last_bar_index:
        if tooltip_window:
            tooltip_window.destroy()
            tooltip_window = None
        
        if current_bar_index >= 0:
            root_x, root_y = root.winfo_pointerx(), root.winfo_pointery()
            tooltip_window = Toplevel(root)
            tooltip_window.wm_overrideredirect(True)
            tooltip_window.wm_geometry(f"+{root_x+10}+{root_y+10}")
            tooltip_window.attributes('-topmost', True)
            
            label_val = labels[current_bar_index]
            count_val = values[current_bar_index]
            details_text = f"Label: {label_val}\nCount: {count_val}\n"
            
            if graph_option.get() == "Packets by Protocol":
                key = str(label_val).lower()
                details = protocol_details.get(key, {})
                if details:
                    top_src = details.get("src_ip", Counter()).most_common(1)
                    top_dst = details.get("dst_ip", Counter()).most_common(1)
                    top_port = details.get("dst_port", Counter()).most_common(1)
                    if top_src:
                        src, cnt = top_src[0]
                        details_text += f"Top Src IP: {src}\n"
                    if top_dst:
                        dst, cnt = top_dst[0]
                        details_text += f"Top Dst IP: {dst}\n"
                    if top_port:
                        port, cnt = top_port[0]
                        details_text += f"Top Dst Port: {port}"
            elif graph_option.get() == "Packets by Source IP":
                key = label_val
                details = src_ip_details.get(key, {})
                if details:
                    top_proto = details.get("protocol", Counter()).most_common(1)
                    top_dst = details.get("dst_ip", Counter()).most_common(1)
                    top_port = details.get("dst_port", Counter()).most_common(1)
                    if top_proto:
                        proto, cnt = top_proto[0]
                        details_text += f"Top Protocol: {proto.upper()}\n"
                    if top_dst:
                        dst, cnt = top_dst[0]
                        details_text += f"Top Dst IP: {dst}\n"
                    if top_port:
                        port, cnt = top_port[0]
                        details_text += f"Top Dst Port: {port}"
            elif graph_option.get() == "Packets by Destination IP":
                key = label_val
                details = dst_ip_details.get(key, {})
                if details:
                    top_proto = details.get("protocol", Counter()).most_common(1)
                    top_src = details.get("src_ip", Counter()).most_common(1)
                    top_port = details.get("dst_port", Counter()).most_common(1)
                    if top_proto:
                        proto, cnt = top_proto[0]
                        details_text += f"Top Protocol: {proto.upper()}\n"
                    if top_src:
                        src, cnt = top_src[0]
                        details_text += f"Top Src IP: {src}\n"
                    if top_port:
                        port, cnt = top_port[0]
                        details_text += f"Top Dst Port: {port}"
            elif graph_option.get() == "Packets by Destination Port":
                key = label_val
                details = dst_port_details.get(key, {})
                if details:
                    top_proto = details.get("protocol", Counter()).most_common(1)
                    top_src = details.get("src_ip", Counter()).most_common(1)
                    top_dst = details.get("dst_ip", Counter()).most_common(1)
                    if top_proto:
                        proto, cnt = top_proto[0]
                        details_text += f"Top Protocol: {proto.upper()}\n"
                    if top_src:
                        src, cnt = top_src[0]
                        details_text += f"Top Src IP: {src}\n"
                    if top_dst:
                        dst, cnt = top_dst[0]
                        details_text += f"Top Dst IP: {dst}"
            
            tooltip_label = Label(tooltip_window, text=details_text, background="lightyellow",
                                  relief="solid", borderwidth=1, padx=5, pady=5,
                                  justify=LEFT, font=("Arial", 9))
            tooltip_label.pack()
        last_bar_index = current_bar_index

def track_mouse_movement(event):
    if tooltip_window:
        root_x, root_y = root.winfo_pointerx(), root.winfo_pointery()
        tooltip_window.wm_geometry(f"+{root_x+10}+{root_y+10}")

def update_graph():
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
    elif selected_view == "Packets by Source MAC":
        data = src_mac_counter
        xlabel = "Source MAC"
    elif selected_view == "Packets by Destination MAC":
        data = dst_mac_counter
        xlabel = "Destination MAC"
    
    ax.clear()
    global bars, labels, values
    if data:
        labels, values = zip(*data.most_common(10))
    else:
        labels, values = ([], [])
    
    bars = ax.bar(range(len(labels)), values, color="skyblue")
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha='right')
    ax.set_title(selected_view)
    ax.set_xlabel(xlabel)
    ax.set_ylabel("Count")
    fig.tight_layout()
    canvas.draw()
    root.after(1000, update_graph)

root = Tk()
root.title("Dynamic On Device Packet Monitoring & Firewall")
root.geometry("1980x1080")

frame = Frame(root)
frame.pack(pady=10)
start_button = Button(frame, text="Start Monitoring", command=start_sniffing_thread)
start_button.pack(side=LEFT, padx=5)
stop_button = Button(frame, text="Stop Monitoring", command=stop_sniffing)
stop_button.pack(side=LEFT, padx=5)
clear_button = Button(frame, text="Clear Logs", command=clear_logs)
clear_button.pack(side=LEFT, padx=5)
log_label = Label(root, text="", fg="blue")
log_label.pack()

# Elapsed Time Label
elapsed_time_label = Label(root, text="Elapsed Time: 0 sec", fg="green")
elapsed_time_label.pack(pady=5)

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

# Blocked IPs Listbox
blocked_frame = Frame(root)
blocked_frame.pack(pady=10, fill=X)
Label(blocked_frame, text="Blocked IPs:").pack(side=LEFT, padx=5)
blocked_list = Listbox(blocked_frame, height=5)
blocked_list.pack(side=LEFT, padx=5)

graph_frame = Frame(root)
graph_frame.pack(pady=10)
Label(graph_frame, text="Select Graph View:").pack(side=LEFT, padx=5)
graph_option = StringVar(value="Packets by Protocol")
# Added two new options for MAC addresses
graph_menu = ttk.Combobox(graph_frame, textvariable=graph_option, 
                          values=["Packets by Protocol", "Packets by Source IP", 
                                  "Packets by Destination IP", "Packets by Destination Port",
                                  "Packets by Source MAC", "Packets by Destination MAC"], 
                          state="readonly", width=25)
graph_menu.pack(side=LEFT, padx=5)

fig, ax = plt.subplots(figsize=(8, 4))
canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().pack(side=RIGHT, fill=BOTH, expand=True)

canvas.mpl_connect("motion_notify_event", on_hover)
root.bind("<Motion>", track_mouse_movement)

bars = []
labels = []
values = []

update_graph()
root.mainloop()
