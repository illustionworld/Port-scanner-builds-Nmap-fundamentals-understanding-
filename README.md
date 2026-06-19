# Port-scanner-builds-Nmap-fundamentals-understanding-
so this a port scanner whare you can learn and understand fundaments understanding 
import argparse
import socket
from concurrent.futures import ThreadPoolExecutor


def scan_port(host, port, timeout=1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((host, port)) == 0:
                return port
    except OSError:
        pass
    return None


def scan_host(host, ports, workers=100, timeout=1.0):
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_port, host, port, timeout): port for port in ports}
        for future in futures:
            port = future.result()
            if port is not None:
                open_ports.append(port)
    return sorted(open_ports)


def parse_port_list(port_text):
    ports = set()
    for token in port_text.split(','):
        token = token.strip()
        if not token:
            continue
        if '-' in token:
            start, end = token.split('-', 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(token))
    return sorted(p for p in ports if 1 <= p <= 65535)


def guess_service(port):
    try:
        return socket.getservbyport(port, 'tcp')
    except OSError:
        return 'unknown'


def main():
    parser = argparse.ArgumentParser(description='Simple Python port scanner for learning Nmap fundamentals')
    parser.add_argument('target', help='Host or IP address to scan')
    parser.add_argument('-p', '--ports', default='1-1024', help='Port list or range, e.g. 22,80,443,1000-1024')
    parser.add_argument('-t', '--timeout', type=float, default=0.8, help='Socket timeout in seconds')
    parser.add_argument('-w', '--workers', type=int, default=100, help='Number of concurrent scan threads')
    args = parser.parse_args()

    try:
        host = socket.gethostbyname(args.target)
    except socket.gaierror as exc:
        print(f'Unable to resolve target: {exc}')
        return

    ports = parse_port_list(args.ports)
    print(f'Scanning {args.target} ({host}) on ports: {args.ports}')
    open_ports = scan_host(host, ports, workers=args.workers, timeout=args.timeout)

    if open_ports:
        print('Open ports:')
        for port in open_ports:
            service = guess_service(port)
            print(f'  {port}/tcp   open    {service}')
    else:
        print('No open ports found.')


if __name__ == '__main__':
    main()
