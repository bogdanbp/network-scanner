import subprocess
import ipaddress
import concurrent.futures
import socket
from scapy.all import ARP, Ether, srp
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# Predefined networks
NETWORKS = [
    "192.168.0.0/24",
    "172.29.14.0/24",
    "172.29.12.0/24",
    "172.29.21.0/24",
    "172.29.22.0/24",
    "172.29.24.0/24",
    "172.29.25.0/24",
    "172.29.26.0/24"
]

IGNORED_IPS = ["172.29.14.254"]

def ping_ip(ip):
    """Check if a host is reachable via ICMP ping."""
    try:
        subprocess.check_output(['ping', '-c', '1', '-W', '1', str(ip)], stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        return False

def arp_scan(network_cidr):
    """Send ARP requests to discover live hosts on the network."""
    arp_results = {}
    try:
        arp = ARP(pdst=network_cidr)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        answered, _ = srp(packet, timeout=2, verbose=False)

        for sent, received in answered:
            arp_results[received.psrc] = "alive"
    except Exception as e:
        print(f"ARP scan error: {e}")
    return arp_results

def port_scan(ip, ports=[22, 80, 443, 3389]):
    """Scan common ports to determine if a host is alive."""
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            if sock.connect_ex((ip, port)) == 0:
                return True
    return False

@app.route('/')
def index():
    """Render the index page with network options."""
    return render_template('index.html', networks=NETWORKS)

@app.route('/scan', methods=['GET'])
def scan():
    """Perform network scan using ARP, ICMP, and port scanning."""
    network_cidr = request.args.get('network')
    if network_cidr not in NETWORKS:
        return jsonify({"error": "Invalid network selected"}), 400

    network = ipaddress.ip_network(network_cidr, strict=False)
    results = {}
    arp_results = arp_scan(network_cidr)

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_ip = {}
        for ip in network.hosts():
            ip_str = str(ip)
            if ip_str in IGNORED_IPS:
                continue
            future_to_ip[executor.submit(ping_ip, ip_str)] = (ip_str, "ICMP")
            future_to_ip[executor.submit(port_scan, ip_str)] = (ip_str, "PORT")

        for future in concurrent.futures.as_completed(future_to_ip):
            ip_str, method = future_to_ip[future]
            try:
                alive = future.result()
            except Exception as exc:
                alive = False

            if alive:
                results[ip_str] = "alive"

    for ip in arp_results:
        results[ip] = "alive"

    return jsonify(results)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
