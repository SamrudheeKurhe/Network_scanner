import subprocess
import socket
import ipaddress
import platform
import threading

def ping(ip, results):
    """Pings a given IP address and updates the results dictionary."""
    try:
        if platform.system() == "Windows":
            subprocess.check_output(["ping", "-n", "1", ip], timeout=1)
        else:
            subprocess.check_output(["ping", "-c", "1", ip], timeout=1)
        results[ip] = True
    except subprocess.CalledProcessError:
        results[ip] = False
    except subprocess.TimeoutExpired:
        results[ip] = False
    except Exception as e:
        print(f"Error pinging {ip}: {e}")
        results[ip] = False

def scan_port(ip, port, open_ports):
    """Tries to connect to a port and adds it to the open_ports list if open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            open_ports.append(port)
    except socket.error:
        pass  # Port is closed or error occurred

def scan_host(ip, results, all_open_ports):
    """Scans a single host for open ports."""
    if results.get(ip):  # Only scan if host is up
        open_ports = []
        threads = []
        for port in COMMON_PORTS:
            thread = threading.Thread(target=scan_port, args=(ip, port, open_ports))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()
        all_open_ports[ip] = open_ports

def scan_network(network_prefix):
    """Scans the network for live hosts and open ports concurrently."""
    results = {}
    threads = []
    for i in range(1, 255):
        ip = f"{network_prefix}.{i}"
        thread = threading.Thread(target=ping, args=(ip, results))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()

    all_open_ports = {}
    threads = []
    for ip in results:
        thread = threading.Thread(target=scan_host, args=(ip, results, all_open_ports))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()

    return all_open_ports

def generate_html_report(results):
    """Generates an HTML report of the scan results."""
    html = "<h1>Network Scan Report</h1>"
    for ip, ports in results.items():
        html += f"<h2>Host: {ip}</h2>"
        if ports:
            html += "<ul>"
            for port in ports:
                html += f"<li>Port {port} is open</li>"
            html += "</ul>"
        else:
            html += "<p>No open ports found.</p>"
    with open("scan_report.html", "w") as f:
        f.write(html)
    print("HTML report generated: scan_report.html")

def get_arp_table():
    """Retrieves and prints the ARP table."""
    try:
        arp_output = subprocess.check_output(["arp", "-a"]).decode()
        print("\nARP Table:\n", arp_output)
    except subprocess.CalledProcessError:
        print("Could not retrieve ARP table.")

if __name__ == "__main__":
    network_prefix = "192.168.1"  # Change to your network
    COMMON_PORTS = [21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 3389]
    scan_results = scan_network(network_prefix)
    generate_html_report(scan_results)
    get_arp_table()