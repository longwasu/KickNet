from scapy.layers.l2 import *
from scapy.layers.inet6 import *

def get_interface():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    src = s.getsockname()[0]
    s.close()

    iface = None
    for i in conf.ifaces:
        if conf.ifaces[i].ip == src:
            return conf.ifaces[i].network_name
    return None
        

def get_gateway():
    gateway_ip = conf.route.route("0.0.0.0")[2]
    return gateway_ip


def get_mac(ipv4):
    packet = Ether(src=get_if_hwaddr(conf.iface))/ARP(pdst=ipv4)
    
    while True:
        ans, _ = srp(packet, iface=conf.iface, timeout=5, verbose=False)
        if ans:
            return ans[0][1][Ether].src
        

def get_ipv6(mac_addr):
    packet_filter = f"ether src {mac_addr} and ip6"
    while True:
        pkts = sniff(iface=conf.iface, count=1, filter=packet_filter)
        ipv6 = pkts[0][IPv6].src
        if ipv6.startswith("fe80::"):
            return ipv6
        

def get_addr6(ipv4):
    mac = get_mac(ipv4)
    ipv6 = get_ipv6(mac)
    return (mac, ipv6)


def get_addr4(ipv4):
    mac = get_mac(ipv4)
    return (mac, ipv4)


def discover_host():
    print("Scanning host...")

    subnet_mask = "/24"
    ip_list = []
    ip_addr = get_if_addr(get_interface())
    ip_gateway = get_gateway()

    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = ip_addr+subnet_mask), timeout=5, inter=0.1, verbose=False)
    for _, recv in ans:
        if recv[ARP].psrc != ip_addr and recv[ARP].psrc != ip_gateway:
            address_pair = (recv[Ether].src, recv[ARP].psrc)
            ip_list.append(address_pair)

    return ip_list