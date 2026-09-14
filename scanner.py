import socket

# Target settings
target_host = "127.0.0.1"  # Scans your local machine
ports_to_scan = [21, 22, 80, 443, 8080]  # Common ports

print(f"[*] Scanning {target_host}...\n")

for port in ports_to_scan:
    # 1. Create an IPv4 (AF_INET), TCP (SOCK_STREAM) socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # 2. Set a 1-second timeout so it doesn't hang indefinitely
    s.settimeout(1.0)

    # 3. Attempt a TCP connection (0 = success)
    result = s.connect_ex((target_host, port))

    if result == 0:
        print(f"[+] Port {port:<5} : OPEN")
    else:
        print(f"[-] Port {port:<5} : Closed/Filtered")

    # 4. Close the connection
    s.close()