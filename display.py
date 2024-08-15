from rich.console import Console
from rich.table import Table
from net_utils import *
import requests

def print_device(addr_list, brand_list):
    table = Table(header_style="bold green")
    table.add_column("No", style="yellow")
    table.add_column("IP Address", style="blue")
    table.add_column("MAC Addresss", style="blue")
    table.add_column("Brand", style="blue")

    for i in range(0, len(addr_list)):
        table.add_row(str(i+1), addr_list[i][1], addr_list[i][0], brand_list[i])
    Console().print(table)


def get_mac_list(addr_list):
    mac_list = []
    for addr in addr_list:
        mac_list.append(addr[0])
    return mac_list
    

def get_brand_name(mac_list):
    brand_list = []

    for mac in mac_list:
        url = f'https://api.maclookup.app/v2/macs/{mac}'
        r = requests.get(url) 
        data = r.json()
        brand_list.append(data.get("company"))
    return brand_list


def get_target_ip():
    while True:
        addr_list = discover_host()
        brand_list = get_brand_name(get_mac_list(addr_list))
        print_device(addr_list, brand_list)

        i = int(input("Enter target number(type 0 for rescan): "))
        if i != 0:
            i -= 1
            break
            
    if i in range(0, len(addr_list)):
        target_ip = addr_list[i][1]
        return target_ip
    else:
        print("Not a valid number!")
        return None