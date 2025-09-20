from scapy.all import sniff
import tkinter as tk
import threading

def show_packet(pkt):
    global packet_sniffed_counter_value
    if pkt.haslayer("IP"):
        source = pkt['IP'].src 
        destination = pkt['IP'].dst
        print(f"Packet: {source} -> {destination}\n Full Packet: {pkt.summary()}")
        text2.config(text="Sniffing packets...")
        button.config(text="Stop Sniffing", command=stop_sniffing)
        packet_sniffed.config(text=f"Packets Sniffed:{pkt.summary()}")
        logs.insert(tk.END, f"<Logs> Sniffed: {pkt.summary()}\n")
        logs.see(tk.END)
        packet_sniffed_counter_value += 1
        packet_sniffed_counter.config(text=f"Total Packets Sniffed: {packet_sniffed_counter_value}")
    elif pkt.haslayer("Ether"):
        source = pkt['Ether'].src 
        destination = pkt['Ether'].dst
        print(f"Packet: {source} -> {destination}\n Full Packet: {pkt.summary()}")
        text2.config(text="Sniffing packets...")
        button.config(text="Stop Sniffing", command=stop_sniffing)
        packet_sniffed.config(text=f"Packets Sniffed:{pkt.summary()}")
        logs.insert(tk.END, f"<Logs> Sniffed: {pkt.summary()}\n")
        logs.see(tk.END)
        packet_sniffed_counter_value += 1
        packet_sniffed_counter.config(text=f"Total Packets Sniffed: {packet_sniffed_counter_value}")
    elif pkt.haslayer("TCP"):
        source = pkt['TCP'].sport 
        destination = pkt['TCP'].dport
        print(f"Packet: {source} -> {destination}\n Full Packet: {pkt.summary()}")
        text2.config(text="Sniffing packets...")
        button.config(text="Stop Sniffing", command=stop_sniffing)
        packet_sniffed.config(text=f"Packets Sniffed:{pkt.summary()}")
        logs.insert(tk.END, f"<Logs> Sniffed: {pkt.summary()}\n")
        logs.see(tk.END)
        packet_sniffed_counter_value += 1
        packet_sniffed_counter.config(text=f"Total Packets Sniffed: {packet_sniffed_counter_value}")
    else:
        packet_sniffed.config(text=f"Packets Sniffed:Cannot parse this packet")
        logs.insert(tk.END, f"<Logs> Sniffed:Failed to parse this packet\n")
        logs.see(tk.END)

def start_sniffing():
    global sniffing
    sniffing = True
    while sniffing:
        sniff(prn=show_packet, filter="ip", store=0)



def start_sniffing_thread():
    thread = threading.Thread(target=start_sniffing)
    thread.daemon = True
    thread.start()

def stop_sniffing():
    global sniffing
    sniffing = False
    text2.config(text="Sniffing stopped.")
    button.config(text="Start Sniffing", command=start_sniffing)

sniffing = False
packet_sniffed_counter_value = 0

root = tk.Tk()
root.title("Packet Sniffer")
root.geometry("600x600")
text = tk.Label(root, text="Welcome to Sigma Packet Sniffer tool",font=("Helvetica", 14))
text.pack(pady=10)
text2 = tk.Label(root, text="Click the button below to start sniffing packets",font=("Helvetica", 10))
text2.pack(pady=5)
packet_sniffed = tk.Label(root, text="Packets Sniffed:",font=("Helvetica", 12))
packet_sniffed.pack(pady=10)
logs = tk.Text(root, height=20, width=50)
logs.pack(pady=10)
packet_sniffed_counter = tk.Label(root, text="Total Packets Sniffed: 0",font=("Helvetica", 12))
packet_sniffed_counter.pack(pady=5)
button = tk.Button(root, text="Start Sniffing", command=start_sniffing_thread)
button.pack(pady=20)


root.mainloop()