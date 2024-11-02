import json, socket, re, os, logging, dis
import subprocess, requests, re, pathlib

from requests.auth import HTTPBasicAuth
from colorama import Fore, Style
from paramiko import SSHClient, AutoAddPolicy
from scp import SCPClient
from ping3 import ping, verbose_ping

import datetime, calendar

logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)


def init_config_args(func_name):
    with open(r'inventory.json') as file:
        data = json.loads(file.read())
        # transfer_files
        if func_name == 'transfer_files':
            transfer = data['config']['native']['methods']['transfer']
            target = transfer['target']
            host = [i for i in data['nodes'] if (i['Ipv4'] == target or i['name'] == target)][0] # get matching ip or name of host 
            return {
                'port' : transfer['port'],
                'user' : host['user'],
                'passw' : host['pass'],
                'method' : transfer['method'],
                'local_path' : transfer['local_path'],
                'remote_path' : transfer['remote_path'],
                'recursive' : transfer['recursive'],
                'preserve_times' : transfer['preserve_times'],
            }
        # send_ping
        elif func_name == 'send_ping':
            return {
                'target' : data['config']['native']['methods']['ping']['target'],
                'verbose' : data['config']['native']['methods']['ping']['verbose'],
                'timeout' : data['config']['native']['methods']['ping']['timeout'],
                'nodes': data['nodes']
            }
        # manage_vm
        elif func_name == 'manage_vm':
            host_ip = data['config']['native']['methods']['virtual_machine']['host']
            node = [i for i in data['nodes'] if (i['Ipv4'] == host_ip or i['name'] == host_ip)][0]
            return {
                'control_method': data['config']['native']['methods']['virtual_machine']['control']['method'],
                'control_runtype': data['config']['native']['methods']['virtual_machine']['control']['type'],
                'control_uuid': data['config']['native']['virtual_machine']['control']['uuid'],
                'network_execution': data['config']['native']['virtual_machine']['natnetwork']['execution_options'],
                'change_system_adapter': data['config']['native']['virtual_machine']['natnetwork']['change_system_adapter'],
                'add': data['config']['native']['virtual_machine']['natnetwork']['add'],
                'modify': data['config']['native']['virtual_machine']['natnetwork']['modify'],
                'node': node,
                'host_ip': host_ip,
                'user': node['user'],
                'passw': node['pass']
            }
        # backup_router
        elif func_name == 'backup_router':
            return {
                'router_ip': data['net_devices']['router']['settings']['Ipv4'],
                'backup_filename': data['config']['native']['methods']['router_backup']['backup_filename'],
                'user': data['net_devices']['router']['user'],
                'pass': data['net_devices']['router']['pass']
            }
        # backup_switch
        elif func_name == 'backup_switch':
            return {
                'switch_ip': data['net_devices']['switch']['settings']['Ipv4'],
                'backup_filename': data['config']['native']['methods']['switch_backup']['backup_filename'],
                'headers': data['config']['native']['methods']['switch_backup']['headers'],
                'user': data['net_devices']['switch']['user'],
                'pass': data['net_devices']['switch']['pass']
            }
        # restore_router
        elif func_name == 'restore_router':
            return {
                'router_ip': data['net_devices']['router']['settings']['Ipv4'],
                'restore_filename': data['config']['native']['methods']['router_restore']['restore_filename'],
                'user': data['net_devices']['router']['user'],
                'pass': data['net_devices']['router']['pass']
            }
        # restore_switch
        elif func_name == 'restore_switch':
            return {
                'switch_ip': data['net_devices']['switch']['settings']['Ipv4'],
                'restore_filename': data['config']['native']['methods']['switch_restore']['restore_filename'],
                'headers': data['config']['native']['methods']['switch_restore']['headers'],
                'user': data['net_devices']['switch']['user'],
                'pass': data['net_devices']['switch']['pass']
            }
        # create_vlan
        elif func_name == 'create_vlan':
            return {
                'switch_ip': data['net_devices']['switch']['settings']['Ipv4'],
                'headers': data['config']['native']['methods']['create_vlan']['headers'],
                'qvlan_add': data['config']['native']['methods']['create_vlan']['qvlan_add'],
                'vid': data['config']['native']['methods']['create_vlan']['vid'],
                'vname': data['config']['native']['methods']['create_vlan']['vname'],
                'port_1': data['config']['native']['methods']['create_vlan']['port_1'],
                'port_2': data['config']['native']['methods']['create_vlan']['port_2'],
                'port_3': data['config']['native']['methods']['create_vlan']['port_3'],
                'port_4': data['config']['native']['methods']['create_vlan']['port_4'],
                'port_5': data['config']['native']['methods']['create_vlan']['port_5'],
                'user': data['net_devices']['switch']['user'],
                'pass': data['net_devices']['switch']['pass']
            } 



# used by functions to authenticate
def _connect_ssh(hostname, port, username, password, allow_agent):
    client = SSHClient()
    if allow_agent != False:
        client.load_host_keys(filename=fr'C:\Users\{os.getlogin()}\.ssh\known_hosts')
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(hostname=hostname, port=port, username=username, password=password, allow_agent=False, look_for_keys=False)
    else:
        client.connect(hostname=hostname, port=port, username=username, password=password, allow_agent=True, look_for_keys=True)
    return (client, client.get_transport())




# transfer files from local to remote computers or vice versa
def transfer_files():
    args = init_config_args('transfer_files')
    # check credentials and operations
    if args['method'] not in ('send', 'get'):
        return print('Must set method to \'send\' or \'get\' in inventory.json config.')
    user = args['user']
    passw = args['passw']
    if user == None:
        user = input('Username: ')
    if passw == None:
        passw = input('Password: ')
    # connect to remote machine
    transport = _connect_ssh(args['Ipv4'], args['port'], user, passw)[1]
    scp = SCPClient(transport)
    # send or get
    if args['method'] == 'send':
        scp.put(files=args['local_path'], remote_path=args['remote_path'], recursive=args['recursive'], preserve_times=args['preserve_times'])
    else:
        scp.get(local_path=args['local_path'], remote_path=args['remote_path'],recursive=args['recursive'], preserve_times=args['preserve_times'])
    scp.close()




# pings devices specified in inventory.json ping config 
def send_ping():
    args = init_config_args('send_ping')
    # prints result of ping displaying hosts and ip addr
    def check_response(ip, response):
        print(response)
        try:
            host = socket.gethostbyaddr(ip)
            if response is None:
                print(f'{Fore.LIGHTYELLOW_EX}{host[0]} ({ip}): {Fore.RED}Timeout{Fore.RESET}')
            elif response is False: 
                print(f'{Fore.LIGHTYELLOW_EX}{host[0]} ({ip}): {Fore.RED}Ping Error{Fore.RESET + Style.RESET_ALL}')
            else:
                print(f'{Fore.LIGHTYELLOW_EX}{host[0]} ({ip}): {Fore.GREEN}UP{Fore.RESET + Style.RESET_ALL}')
        except:
            if response is None:
                print(f'{Fore.LIGHTYELLOW_EX} ({ip}): {Fore.RED}Timeout{Fore.RESET}')
            elif response is False: 
                print(f'{Fore.LIGHTYELLOW_EX} ({ip}): {Fore.RED}Ping Error{Fore.RESET + Style.RESET_ALL}')
            else:
                print(f'{Fore.LIGHTYELLOW_EX} ({ip}): {Fore.GREEN}UP{Fore.RESET + Style.RESET_ALL}')

    def ping_target(t, timeout, verbose):
        ip = t
        # check if value matches that of ip addr in the subnet
        r = re.compile(r"^192\.168\.1\.\b([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5])$")
        match = r.search(string=ip)
        # if the target is in the form of an ip address 
        if match:
            response = ping(ip, timeout=timeout)
            if verbose:
                verbose_ping(ip, timeout=timeout)
            check_response(ip, response)
        # if target is in the form of a host name
        else:
            try:
                print(t)
                ip = socket.gethostbyname(t)
            except socket.gaierror:
                return print(f'{ip}: {Fore.LIGHTMAGENTA_EX}Hostname not found / Unreachable{Fore.RESET}')
            response = ping(ip, timeout=timeout)
            if verbose:
                verbose_ping(ip, timeout=timeout)
            check_response(ip, response)

    # get all node ip addresses
    if args['target'] == '*':  
        [ping_target(i['Ipv4'], args['timeout'], args['verbose']) for i in args['nodes']]
    else:
        ping_target(args['target'], args['timeout'], args['verbose'])




def _manage_vm_control_method(args: dict, transport: SSHClient, control_method: str):
    control_method_options = {
        'startvm' : transport.exec_command(f"VBoxManage {args['control_method']} {args['control_uuid']} --password-id {args['passw']} --type={args['runtype']}")[1],
        'pause': transport.exec_command(f"VBoxManage controlvm {args['control_uuid']} {args['control_method']}")[1],
        'resume': transport.exec_command(f"VBoxManage controlvm {args['control_uuid']} {args['control_method']}")[1],
        'reset': transport.exec_command(f"VBoxManage controlvm {args['control_uuid']} {args['control_method']}")[1],
        'poweroff': transport.exec_command(f"VBoxManage controlvm {args['control_uuid']} {args['control_method']}")[1],
        'savestate': transport.exec_command(f"VBoxManage controlvm {args['control_uuid']} {args['control_method']}")[1],
        'reboot': transport.exec_command(f"VBoxManage controlvm {args['control_uuid']} {args['control_method']}")[1],
        'shutdown': transport.exec_command(f"VBoxManage controlvm {args['control_uuid']} {args['control_method']}")[1],
        'list runningvms': transport.exec_command(f"VBoxManage {args['control_method']}")[1],
        'list vms': transport.exec_command(f"VBoxManage {args['control_method']}")[1]
    }
    # determines if the output of the command will be read with a for loop or readline()
    should_read_line = True if (control_method == 'list runningvms' or 'list vms') else False
    return (control_method_options[control_method], should_read_line)

# manages virtual machines on hosts in local network
def manage_vm():
    # read arguments from inventory.json
    args = init_config_args('manage_vm')
    print(args['method'])
    # connect to virtual machine
    try:
        transport = _connect_ssh(hostname=args['host_ip'], port=22, username=args['user'], password=args['passw'])[0]
    except TimeoutError:
        return print(f'Connection to {args["host_ip"]} timed out')
    # control virtual machine
    # TODO: finish implementing vm machines
    out, should_read_line = _manage_vm_control_method(args['control_method'])
    # read output
    if should_read_line == True:
        out.readline()
    else:
        for i in out:
            print(i)
    if args['execution_options']:
        for option in args['execution_options']:
            # command to add a new natnetwork in VirtualBox
            if option == 'add':
                enable_opt = '--enable' if args['add']['enable'] == True else '--disable'
                natname = args['add']['netname']
                network_prefix = args['add']['network_prefix']
                dhcp = 'on' if args['add']['enable_dhcp'] == True else 'off'
                ipv6 = 'on' if args['add']['enable_ipv6'] == True else 'off'
                command = f"VBoxManage natnetwork add {enable_opt} --netname={natname} --network={network_prefix} --dhcp={dhcp} --ipv6={ipv6}"
                inp, out, err = transport.exec_command(command)
                out.readline()
            # command to modify a natnetwork in VirtualBox
            if option == 'modify':
                enable_opt = '--enable' if args['modify']['enable'] == True else '--disable'
                natname = args['modify']['netname']
                network_prefix = args['modify']['network_prefix']
                dhcp = 'on' if args['modify']['enable_dhcp'] == True else 'off'
                ipv6 = 'on' if args['modify']['enable_ipv6'] == True else 'off'
                command = f"VBoxManage natnetwork modify {enable_opt} --netname={natname} --network={network_prefix} --dhcp={dhcp} --ipv6={ipv6}"
                inp, out, err = transport.exec_command(command)
                out.readline()
            # change a VM's network adapter
            if option == 'change_system_adapter':
                uuid = args['change_system_adapter']['uuid']
                adapter_num = args['change_system_adapter']['adapter_num']
                nat_net_name = args['change_system_adapter']['nat_net_name']
                command = f"VBoxManage modifyvm {uuid} --nat-net{adapter_num}={nat_net_name}"
                inp, out, err = transport.exec_command(command)
                out.readline()

    

# save router configuration to backup folder
def backup_router():
    # config file parameter initialization
    args = init_config_args('backup_router')
    router_ip = args['router_ip']
    user = args['user']
    password = args['pass']
    # set backup path information
    path = fr'C:\Users\{os.getlogin()}\OneDrive\Desktop\python-scripts\networking\Orca\admin\backups\router'
    backup_dir = os.listdir(path)
    backup_filename = args['backup_filename'] if args['backup_filename'] is not None or "" else f'backup{len(backup_dir) + 1}'
    print(backup_filename)
    # request setup and authentication
    conn = _connect_ssh(router_ip, 22, user, password, True)
    client = conn[0]
    transport = conn[1]
    stdin, stdout, stderr = client.exec_command(f'/system backup save name={backup_filename}')
    for i in stdout:
        print(i)
    scp = SCPClient(transport)
    scp.get(remote_path=fr'./{backup_filename}.backup', local_path=path)
    print(fr'Orca\admin\backups\router\{backup_filename} backup complete.')




# login and download most recent backup file without initiating the backup
def download_backup():
    args = init_config_args('backup_router')
    client = _connect_ssh('192.168.88.1', 22, args['user'], args['pass'], True)
    transport = client[1]
    # get current backup file name
    y = datetime.datetime.now().year 
    m = (calendar.month_name[datetime.datetime.now().month])[0:3].lower()
    d = datetime.datetime.now().day if datetime.datetime.now().day > 10 else f'{0}{datetime.datetime.now().day}'
    backup_filename = fr"{m}-{d}-{y}.backup"
    # save backup file
    scp = SCPClient(transport)
    scp.get(remote_path=f'./{backup_filename}', local_path=fr'C:\Users\{os.getlogin()}\OneDrive\Desktop\python-scripts\networking\Orca\admin\backups\router')




# save switch configuration to backup folder
def backup_switch():
    args = init_config_args('backup_switch')
    switch_ip = args['switch_ip']
    headers = args['headers']
    user = args['user']
    password = args['pass']
    backup_filename = args['backup_filename'] if args['backup_filename'] is not None or "" else None

    # request setup and authentication
    url = fr'http://{switch_ip}/config_back.cgi?btnBackup=Backup+Config'
    auth = HTTPBasicAuth(user, password)
    res = requests.get(url=url, headers=headers, auth=auth)
    
    # scrape content
    file_name = res.headers['Content-Disposition']
    file_content = res.content
    r = re.search('filename=([^;]+)', file_name)
    # increment count of backups by 1
    backup_count = len(os.listdir(fr'C:\Users\{os.getlogin()}\OneDrive\Desktop\python-scripts\networking\Orca\admin\backups\switch')) + 1
    save_file_name = r.group(1).replace('.', fr'_{backup_count}.') if backup_filename is None else backup_filename

    print(f'Status: {res.status_code}')
    print(f'save to file: {save_file_name}')

    # write content to file
    with open(fr'C:\Users\{os.getlogin()}\OneDrive\Desktop\python-scripts\networking\Orca\admin\backups\switch\{save_file_name}', 'wb') as f:
        f.write(file_content)
    print(fr'Orca\admin\backups\switch\{save_file_name} backup complete.')



# restore router configuration from backup folder
def restore_router():
    # config file parameter initialization
    args = init_config_args('restore_router')
    router_ip = args['router_ip']
    restore_filename = args['restore_filename']
    user = args['user']
    password = args['pass']
    # get backup file name
    path = fr'C:\Users\{os.getlogin()}\OneDrive\Desktop\python-scripts\networking\Orca\admin\backups\router'
    restore_filename = os.listdir(path)[-1] if restore_filename is None else None 
    # request setup and authentication
    conn = _connect_ssh(router_ip, 22, user, password, True)
    client = conn[0]
    transport = conn[1]
    # transfer backup file to router
    scp = SCPClient(transport)
    scp.put(files=f'{path}\{restore_filename}', remote_path=fr'./{restore_filename}')
    print(fr'Orca\admin\backups\router\{restore_filename} restoration performed.')
    # execute router command to restore the backup
    stdin, stdout, stderr = client.exec_command(f'/system backup load name={restore_filename} password=[]')
    for i in stdout:
        print(i)



# restore switch configuration from backup folder
def restore_switch():
    args = init_config_args('restore_switch')
    switch_ip = args['switch_ip']
    headers = args['headers']
    restore_filename = args['restore_filename']
    user = args['user']
    password = args['pass']
    auth = HTTPBasicAuth(user, password)

    if restore_filename is None:
        restore_filename = os.listdir(fr'C:\Users\{os.getlogin()}\OneDrive\Desktop\python-scripts\networking\Orca\admin\backups\router')[-1]

    # read file data into payload
    with open(fr'C:\Users\{os.getlogin()}\OneDrive\Desktop\python-scripts\networking\Orca\admin\backups\switch\{restore_filename}', 'rb') as f:
        payload = f.read()

    url = fr'http://{switch_ip}/conf_restore.cgi'
    res = requests.post(url=url, headers=headers, data=payload, auth=auth)
    print(res.status_code)



# Create a vlan based on inventory configuration parameters
def create_vlan():
    # 0 - untagged
    # 1 - tagged
    # 2 - exempt
    args = init_config_args('create_vlan')
    switch_ip = args['switch_ip']
    headers = args['headers']
    user = args['user']
    password = args['pass']
    auth = HTTPBasicAuth(user, password)
    payload = {
        "vid": args['vid'],
        "vname": args['vname'],
        "selType_1": args['port_1'],
        "selType_2": args['port_2'],
        "selType_3": args['port_3'],
        "selType_4": args['port_4'],
        "selType_5": args['port_5'],
        "qvlan_add": args['qvlan_add'] 
    }
    # print(payload)
    # print(headers)
    url = f"http://{switch_ip}/qvlanSet.cgi"
    # make request
    res = requests.get(url=url, headers=headers, params=payload, auth=auth)
    print(res.status_code)
    print(f"vid: {args['vid']}, vname: {args['vname']} created.")



# TODO: implement function to wake devices remotely
def send_magic_packet(mac_address, broadcast_ip="192.168.1.255", port=9):
    # Convert MAC address to binary format
    mac_bytes = bytes.fromhex(mac_address.replace('-', ''))
    # Construct magic packet
    magic_packet = b'\xff' * 6 + mac_bytes * 16
    # Create UDP socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # Set socket options to allow broadcasting
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # Send magic packet to broadcast IP and port
        sock.sendto(magic_packet, (broadcast_ip, port))



# configure valid extensions here 
native_export = {
    'transfer': {
        'method': transfer_files,
        'description': 'Copies files to and from remote hosts on the local network.'
    },
    'ping': {
        'method': send_ping,
        'description': 'Sends an ICMP Echo Request to check if hosts are up.'
    },
    'virtual_machine': {
        'method': manage_vm,
        'description': 'Various commands to control VirtualBox VMs on remote hosts.'
    },
    'backup_router': {
        'method': backup_router,
        'description': 'Saves router configuration to the admin folder.'
    },
    'backup_switch': {
        'method': backup_switch,
        'description': 'Saves switch configuration to the admin folder.'
    },
    'download_backup': {
        'method': download_backup,
        'description': 'downloads the current day backup from the router'
    },
    'restore_router': {
        'method': restore_router,
        'description': 'Saves router configuration to the admin folder.'
    },
    'restore_switch': {
        'method': restore_switch,
        'description': 'Saves switch configuration to the admin folder.'
    },
    'create_vlan': {
        'method': create_vlan,
        'description': 'Creates a VLAN by specifying if devices are untagged, tagged, or exempt.'
    }
}


if __name__ == '__main__':
    send_ping()
    # transfer_files()
    # send_magic_packet('38-a3-8c-60-65-b6')
    # manage_vm()
    # backup_router()
    # backup_switch()
    # download_backup()
    # restore_router()
    # restore_switch()
    # create_vlan()