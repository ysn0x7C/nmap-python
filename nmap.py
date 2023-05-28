import nmap

def network_scan(target_ip):
    scanner = nmap.PortScanner()
    scanner.scan(target_ip, arguments='-F -O -sV')  # Perform fast scan with OS detection and service version detection

    devices = []
    
    for host in scanner.all_hosts():
        device = {
            'ip': host,
            'mac': scanner[host]['addresses']['mac']
        }
        if 'osmatch' in scanner[host]:
            device['os'] = scanner[host]['osmatch'][0]['name']
        if 'hostnames' in scanner[host]:
            device['hostname'] = scanner[host]['hostnames'][0]['name']
        
        open_ports = []
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                service = {
                    'port': port,
                    'name': scanner[host][proto][port]['name'],
                    'state': scanner[host][proto][port]['state'],
                    'product': scanner[host][proto][port]['product'],
                    'version': scanner[host][proto][port]['version'],
                    'extrainfo': scanner[host][proto][port]['extrainfo'],
                }
                open_ports.append(service)
        
        device['open_ports'] = open_ports
        devices.append(device)
    
    return devices

def print_devices(devices):
    print("Discovered devices:")
    print("IP\t\t\tMAC Address\t\t\tHostname\t\t\tOperating System")
    print("--------------------------------------------------------------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t{device['mac']}\t{device.get('hostname', '')}\t\t{device.get('os', '')}")
        print("Open Ports:")
        for port in device['open_ports']:
            print(f"- Port: {port['port']}\tState: {port['state']}\tService: {port['name']}\tProduct: {port['product']}\tVersion: {port['version']}")
        print("--------------------------------------------------------------------------------------------")

# Usage example
target_ip = '192.168.1.1/24'  # Enter the IP range or specific IP address of the network to scan
scan_results = network_scan(target_ip)
print_devices(scan_results)

