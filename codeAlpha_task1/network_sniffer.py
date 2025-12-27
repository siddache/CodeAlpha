from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
from datetime import datetime

# Function to handle and display captured packets
def packet_handler(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Determine the protocol type
        protocol = ""
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        else:
            protocol = "Other"

        # Create log entry with timestamp
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {protocol} Packet: {ip_src} -> {ip_dst}\n"

        # Print packet details
        print(log_entry.strip())

        # Log packet details to a file
        with open("packet_logs.txt", "a") as log_file:
            log_file.write(log_entry)

# Function to start the sniffer
def start_sniffer(interface=None):
    print("Starting network sniffer...")
    print(f"Capturing packets on interface: {interface if interface else 'default'}")
    print("Press Ctrl+C to stop the sniffer.\n")

    # Start sniffing packets on specified interface
    try:
        sniff(prn=packet_handler, iface=interface, store=False)
    except Exception as e:
        print(f"Error: {e}. Please make sure the interface is correct and you have the necessary permissions.")

# Function to list available network interfaces
def list_interfaces():
    interfaces = get_if_list()
    print("Available Network Interfaces:")
    for index, iface in enumerate(interfaces):
        print(f"{index + 1}. {iface}")
    print()
    return interfaces

# Main function with a menu for user options
def main():
    print("Welcome to the Custom Network Sniffer")
    print("1. Sniff on Default Interface")
    print("2. Sniff on Specific Interface")
    print("3. List Available Interfaces")
    print("4. Exit")

    # Get user choice
    choice = input("Enter your choice (1/2/3/4): ").strip()

    if choice == '1':
        start_sniffer()
    elif choice == '2':
        interface = input("Enter the interface to sniff on (e.g., Ethernet, Wi-Fi): ").strip()
        start_sniffer(interface)
    elif choice == '3':
        list_interfaces()
        main()  # Show the menu again after listing interfaces
    elif choice == '4':
        print("Exiting the sniffer.")
    else:
        print("Invalid choice! Please select a valid option.")
        main()

if __name__ == "__main__":
    main()