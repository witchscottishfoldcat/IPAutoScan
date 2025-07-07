import nmap
from colorama import Fore, Back, Style, init
from prettytable import PrettyTable
import ipaddress

init(autoreset=True)

# @lianziyang 2025-4-27

def print_banner():
    print(Fore.CYAN + "\n" + "=" * 50)
    print(Fore.YELLOW + "Nmap 自动化扫描工具")
    print(Fore.CYAN + "=" * 50 + Style.RESET_ALL)

def print_error(message):
    print(Fore.RED + f"[!] 错误: {message}" + Style.RESET_ALL)

def print_success(message):
    print(Fore.GREEN + f"[+] {message}" + Style.RESET_ALL)

def print_warning(message):
    print(Fore.YELLOW + f"[!] 注意: {message}" + Style.RESET_ALL)

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_network(net):
    try:
        ipaddress.ip_network(net, strict=False)
        return True
    except ValueError:
        return False

def tcp_syn_scan(ip, ports):
    try:
        scanner.scan(ip, ports, '-v -sS')
        if scanner[ip].state() == "up":
            table = PrettyTable()
            table.field_names = [Fore.YELLOW + "协议", "端口", "状态" + Style.RESET_ALL]
            for proto in scanner[ip].all_protocols():
                for port in scanner[ip][proto].keys():
                    table.add_row([proto.upper(), port, Fore.GREEN + "开放" + Style.RESET_ALL])
            print(table)
        else:
            print_warning(f"主机 {ip} 似乎不可达")
    except Exception as e:
        print_error(f"扫描失败: {str(e)}")

def udp_scan(ip, ports):
    try:
        scanner.scan(ip, ports, '-v -sU')
        if scanner[ip].state() == "up":
            table = PrettyTable()
            table.field_names = [Fore.YELLOW + "协议", "端口", "状态" + Style.RESET_ALL]
            if 'udp' in scanner[ip]:
                for port in scanner[ip]['udp']:
                    table.add_row(["UDP", port, Fore.GREEN + "开放" + Style.RESET_ALL])
                print(table)
            else:
                print_warning("未发现开放UDP端口")
        else:
            print_warning(f"主机 {ip} 似乎不可达")
    except Exception as e:
        print_error(f"扫描失败: {str(e)}")

def version_scan(ip, ports):
    try:
        scanner.scan(ip, ports, '-v -sV')
        if scanner[ip].state() == "up":
            table = PrettyTable()
            table.field_names = [Fore.YELLOW + "协议", "端口", "服务", "版本" + Style.RESET_ALL]
            for proto in scanner[ip].all_protocols():
                for port in scanner[ip][proto]:
                    service = scanner[ip][proto][port]['name']
                    version = scanner[ip][proto][port]['product'] + ' ' + scanner[ip][proto][port]['version']
                    table.add_row([proto.upper(), port, service, version])
            print(table)
        else:
            print_warning(f"主机 {ip} 似乎不可达")
    except Exception as e:
        print_error(f"扫描失败: {str(e)}")

def quick_scan(ip):
    try:
        scanner.scan(ip, arguments='-F')
        if scanner[ip].state() == "up":
            table = PrettyTable()
            table.field_names = [Fore.YELLOW + "协议", "端口", "状态" + Style.RESET_ALL]
            for proto in scanner[ip].all_protocols():
                for port in scanner[ip][proto]:
                    table.add_row([proto.upper(), port, Fore.GREEN + "开放" + Style.RESET_ALL])
            print(table)
        else:
            print_warning(f"主机 {ip} 似乎不可达")
    except Exception as e:
        print_error(f"扫描失败: {str(e)}")

def os_detection(ip):
    try:
        scanner.scan(ip, arguments='-O')
        if 'osmatch' in scanner[ip]:
            table = PrettyTable()
            table.field_names = [Fore.YELLOW + "操作系统", "准确率" + Style.RESET_ALL]
            for osmatch in scanner[ip]['osmatch']:
                table.add_row([osmatch['name'], f"{osmatch['accuracy']}%"])
            print(table)
        else:
            print_warning("未能识别操作系统")
    except Exception as e:
        print_error(f"扫描失败: {str(e)}")

def network_scan(network):
    try:
        scanner.scan(hosts=network, arguments='-sn')
        table = PrettyTable()
        table.field_names = [Fore.YELLOW + "IP地址", "状态" + Style.RESET_ALL]
        for host in scanner.all_hosts():
            if scanner[host].state() == 'up':
                table.add_row([host, Fore.GREEN + "在线" + Style.RESET_ALL])
        print(table)
    except Exception as e:
        print_error(f"扫描失败: {str(e)}")

print_banner()
scanner = nmap.PortScanner()

ip_addr = '172.16.1.1'  # 默认扫描地址

menu = """请选择扫描任务：
1. TCP SYN扫描 (1-4000端口)
2. UDP扫描 (1-1024端口)
3. 服务版本扫描 (1-4000端口)
4. 快速默认扫描
5. 操作系统检测
6. 自定义IP扫描
7. 网络发现扫描
请选择 (1-7): """

try:
    response = input(Fore.CYAN + menu + Style.RESET_ALL)

    if response == '1':
        print_success("正在进行TCP SYN扫描...")
        tcp_syn_scan(ip_addr, '1-10')

    elif response == '2':
        print_success("正在进行UDP扫描...")
        udp_scan(ip_addr, '1-10')

    elif response == '3':
        print_success("正在进行服务版本扫描...")
        version_scan(ip_addr, '1-10')

    elif response == '4':
        print_success("正在进行快速默认扫描...")
        quick_scan(ip_addr)

    elif response == '5':
        print_success("正在进行操作系统检测...")
        os_detection(ip_addr)

    elif response == '6':
        custom_ip = input("请输入要扫描的IP地址: ")
        if validate_ip(custom_ip):
            port_range = input("请输入端口范围 (默认1-4000): ") or '1-2'
            tcp_syn_scan(custom_ip, port_range)
        else:
            print_error("无效的IP地址格式")

    elif response == '7':
        network = input("请输入要扫描的网段 (例如 192.168.1.0/24): ")
        if validate_network(network):
            print_success(f"正在扫描网络 {network}...")
            network_scan(network)
        else:
            print_error("无效的网络地址格式")

    else:
        print_error("无效的选项")

except KeyboardInterrupt:
    print_error("用户中断操作")
except nmap.PortScannerError as e:
    print_error(f"Nmap操作失败: {str(e)}")
    print_warning("某些扫描可能需要管理员权限，请尝试使用sudo运行")
except Exception as e:
    print_error(f"发生未预期错误: {str(e)}")
finally:
    print(Fore.CYAN + "\n扫描任务结束，感谢使用！" + Style.RESET_ALL)