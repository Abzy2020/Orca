import json, argparse, sys
from colorama import Fore
from threading import Thread
from paramiko import SSHClient
from native_commands.extensions import native_export



class Node:
    def __init__(self, name, Ipv4):
        self.name = name
        self.Ipv4 = Ipv4


class Inventory:
    def __init__(self):
        self.nodes_record = {}
        self.init_inventory()
    
    def add_node(self, host: Node):
        self.nodes_record.update({host.name : 
            {
                "name": host.name, 
                "Ipv4": host.Ipv4
            }
        })

    # read inventory data
    def init_inventory(self):
        with open(r'inventory.json', 'r') as f:
            inv = json.loads(f.read())
            nodes = inv['nodes']
            for node in nodes:
                host = Node(node["name"], node["Ipv4"])
                self.add_node(host)

    # list all or specified nodes in inventory
    def enumerate_inventory(self, name: str):
        if name == '*':
            print(f'{Fore.CYAN}Inventory:{Fore.RESET}')
            print(json.dumps(self.nodes_record, indent=4))
        else:
            print(f'{Fore.CYAN}Node:{Fore.RESET}')
            print(json.dumps(self.nodes_record.get(name), indent=4))

    def count(self):
        return len(self.nodes_record)


class Orchestrator:
    def __init__(self, inventory: Inventory):
        self.inventory = inventory
        self.commands = self._init_config()  # read commands into list
        self.thread_pool = []
        # add native commands here
        self.native = native_export

    # read config data
    def _init_config(self) -> list:
        with open(r'inventory.json', 'r') as f:
            inv = json.loads(f.read())
            commands = inv['config']['script']
            return commands
        
    # run commands on the target(s)
    def run_commands(self, target='*'):
        if target == '*':
            # for each host
            for i in self.inventory.nodes_record:
                # get the IP address
                ip = self.inventory.nodes_record.get(i)["Ipv4"]
                self._run_thread(ip, args=[ip], func=self.connect_and_run)
        elif type(target) is list:
            for i in target:
                ip = self.inventory.nodes_record.get(i)["Ipv4"]
                self._run_thread(ip, args=[ip], func=self.connect_and_run)
        else:
            ip = self.inventory.nodes_record.get(target)["Ipv4"]
            self._run_thread(ip, args=[ip], func=self.connect_and_run)

    def _run_thread(self, name, args, func):
        t = Thread(target=func, name=name, args=args)
        t.run()
            
    def connect_and_run(self, ip):
        with open(r'inventory.json', 'r') as f:
            data = json.loads(f.read())
            known_hosts = data['config']['authentication']['host_key_path']
        # connect to the target host
        client = SSHClient()
        client.load_host_keys(f'{known_hosts}')
        user = "zcool"
        password = "wally1dog"
        client.connect(hostname=ip, username=user, password=password)
        # run commands
        self._exec_handler(client)
        # close channel
        client.close()

    def _exec_handler(self, client: SSHClient):
        # read commands from inventory.json
        if len(self.commands) >= 1:
            print()
            # TODO: make the output of commands a dictionary with keys for output and error
            for command in self.commands:
                # get response information
                stdin, stdout, stderr = client.exec_command(command)
                # successfully ran command
                for line in stdout:
                    print(line, end='')
                # error running command
                for line in stderr:
                    print(line, end='')
            print()
        else:
            print("No commands specified in inventory.json config script.")

    def call_native(self, method):
        if method not in self.native:
            return print('Method not implemented')
        # call function from native dict and run in a thread
        self.run_thread(name=method, args=[],func=self.native[method]['method'])

    def show_native_commands(self):
        print()
        native_str = [f'Native Commands:']
        for command in self.native:
            description = self.native[command]['description']
            comm = '\n{:<23} {:<23}'.format(command, description)
            #print('{:<23} {:<23}'.format(command, description))
            native_str.append(comm)
        return ''.join(native_str)
        


def main():
    cmdlist = lambda s: s.split(',') # parses args in the form: 'arg1','arg2','arg3'
    inventory = Inventory()
    orca = Orchestrator(inventory)
    p = argparse.ArgumentParser(
        prog='Orca', 
        description='Manages devices in the IT environment.', 
        epilog=orca.show_native_commands(), 
        formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument('--enumerate', metavar='Host', type=str, action='store',  help='Prints one or more hosts in your inventory.json file.')
    p.add_argument('--command', metavar='Host', type=cmdlist, action='store',help='Runs commands on one or more hosts.')
    p.add_argument('--native', type=str, action='store', choices=[i for i in orca.native]+['show'],help='Runs commands on one or more hosts.')

    args = p.parse_args()
    # identify all devices
    if args.enumerate:
        inventory.enumerate_inventory(args.enumerate)    
    # run commands specified in the 'script' section of inventory.json on device(s)
    elif args.command:
        orca.run_commands(args.command)
    # call native command
    elif args.native:
        if args.native == 'show':
            orca.show_native_commands()
        else:
            orca.call_native(args.native)
    else:
        p.print_help()



if __name__ == '__main__':
    main()