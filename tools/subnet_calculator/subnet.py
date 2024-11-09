import math

# subnetting calculator

# INPUT PARAMS: ip address, cidr notation or subnet mask

# OUTPUT: IP Address, IP Class/Network, Subnet Count, Assignable Host Count, Network address, first host, last host, broadcast address


# formula lambda functions
calc_subnet_count = lambda network_cidr, classful_cidr: 2 ** (network_cidr - classful_cidr)     # 2^(borrowed bits)
calc_assignable_ips = lambda network_cidr: 2 ** (32 - network_cidr) - 2                         # 2^(host bits) - 2


# translates binary string to decimal number
def bin_to_dec(binary):
    val = 0
    hmap = {'1': 1, '2': 2, '3': 4, '4': 8, '5': 16, '6': 32, '7': 64, '8': 128}
    for i, b in enumerate(binary[::-1]):
        pos = i + 1
        if b == '1':
            val += hmap.get(str(pos))
            # print(f"pos: {pos}, bit: {b}, current_val: {val}")
    return val


# translates a decimal number to a binary string
def dec_to_bin(decimal):
    binary = ['0', '0', '0', '0', '0', '0', '0', '0'] 
    hmap = {'128': 8, '64': 7, '32': 6, '16': 5, '8': 4, '4': 3, '2': 2, '1': 1}
    for i in hmap:
        num = int(i)
        # print(f'current number: {num}')
        if num <= decimal:
            # print(num)
            index = hmap.get(i) - 1
            binary[index] = '1'
            # print(f'current number: {num}, dec: {decimal}')
            decimal -= num
    new_binary_number = "".join(binary[::-1])
    # print(new_binary_number)
    return new_binary_number


def print_subnet_info(subnet_info: dict, cidr: int):
    net_addr = subnet_info.get('net_addr')
    first_host = subnet_info.get('first_host')
    last_host = subnet_info.get('last_host')
    broad_addr = subnet_info.get('broad_addr')
    network_class = subnet_info.get('network_class')
    print(f"Network Class: {network_class}")
    print(f"Network Address: {net_addr}/{cidr}")
    print(f"First assignable host: {first_host}/{cidr}")
    print(f"Last assignable host: {last_host}/{cidr}")
    print(f"Broadcast Address: {broad_addr}/{cidr}")


def get_network_class(ip: str):
    ip_class = {0: 'A', 1: 'B', 2: 'C', 3: 'D', 4: 'E'}
    # check first octet for the class
    if 1 <= int(ip.split('.')[0]) <= 127:
        return ip_class.get(0)
    elif 128 <= int(ip.split('.')[0]) <= 191:
        return ip_class.get(1)
    elif 192 <= int(ip.split('.')[0]) <= 223:
        return ip_class.get(2)
    elif 224 <= int(ip.split('.')[0]) <= 239:
        return ip_class.get(3)
    elif 240 <= int(ip.split('.')[0]) <= 255:
        return ip_class.get(4)


def get_increment(octet_position, assignable_ips):
    if octet_position == 3:
        return assignable_ips + 2
    elif octet_position == 2:
        return math.ceil(assignable_ips / 256)
    elif octet_position == 1:
        return math.ceil(assignable_ips / 65536)
    elif octet_position == 0:
        return math.ceil(assignable_ips / 16777216)
    

def get_network_and_broadcast_addrs(ip: str, subnet_count: int, assignable_ips: int, octet_position: int, **kwargs):
    ip_class = get_network_class(ip)
    # split the ip address by the dots
    octets = ip.split('.')
    oct_start = 0
    network_part = octets[0:octet_position]
    current_octet = octets[octet_position]
    increment = get_increment(octet_position, assignable_ips)

    if octet_position == 3:
        oct_end = oct_start + (subnet_count - 1) if subnet_count > 1 else 255
    else:
        oct_end = oct_start + increment - 1

    while True:
        if oct_start <= int(current_octet) <= oct_end:
            results = {
                3: {'net_addr': f"{'.'.join(network_part)}.{oct_start}", 'first_host': f"{'.'.join(network_part)}.{oct_start + 1}",'last_host': f"{'.'.join(network_part)}.{oct_end - 1}", 'broad_addr': f"{'.'.join(network_part)}.{oct_end}",'network_class': ip_class},
                2: {'net_addr': f"{'.'.join(network_part)}.{oct_start}.{0}", 'first_host': f"{'.'.join(network_part)}.{oct_start}.{1}",'last_host': f"{'.'.join(network_part)}.{oct_end}.{254}", 'broad_addr': f"{'.'.join(network_part)}.{oct_end}.{255}",'network_class': ip_class},
                1: {'net_addr': f"{'.'.join(network_part)}.{oct_start}.{0}.{0}", 'first_host': f"{'.'.join(network_part)}.{oct_start}.{0}.{1}",'last_host': f"{'.'.join(network_part)}.{oct_end}.{255}.{254}", 'broad_addr': f"{'.'.join(network_part)}.{oct_end}.{255}.{255}",'network_class': ip_class},
                0: {'net_addr': f"{oct_start}.{0}.{0}.{0}", 'first_host': f"{oct_start}.{0}.{0}.{1}",'last_host': f"{oct_end}.{255}.{255}.{254}", 'broad_addr': f"{oct_end}.{255}.{255}.{255}",'network_class': ip_class}
            }
            return results[octet_position]
        oct_start += increment
        oct_end += increment


def organize_info(ip: str, cidr: int, classful_cidr: int, octet_position: int):
    # calculate subnet and host counts
    subnet_count = calc_subnet_count(cidr, classful_cidr)
    assignable_ips = calc_assignable_ips(cidr)
    # get specific subnet information
    subnet_info = get_network_and_broadcast_addrs(ip, subnet_count, assignable_ips, octet_position)
    print(f'Subnet count: {subnet_count}\nIP Address count: {assignable_ips + 2}\nHost count: {assignable_ips}\n')
    # display subnet information
    print_subnet_info(subnet_info, cidr)


def get_subnet_and_ip_addr_count(ip: str, cidr: int | None, subnet_mask: str | None):
    # input validation
    octets = ip.split('.')
    for i in octets:
        if int(i) < 0 or int(i) > 255:
            print('Invalid IP range')
            return
    if cidr == None:
        split_mask = subnet_mask.split('.')
        binary_form = ''
        for i, bits in enumerate(split_mask):
            binary_form += f"{dec_to_bin(int(bits))}." if i < 3 else f"{dec_to_bin(int(bits))}"
        cidr = binary_form.count('1')
    print(f'IP Address: {ip}/{cidr}', end='\n\n')
    if cidr < 8:                            # 00000000.00000000.00000000.00000000 - 11111110.00000000.00000000.00000000 
        organize_info(ip, cidr, 0, 0)
    if cidr >= 8 and cidr < 16:             # 11111111.00000000.00000000.00000000 - 11111111.11111111.00000000.00000000 
        organize_info(ip, cidr, 8, 1)
    if cidr >= 16 and cidr < 24:            # 11111111.11111111.00000000.00000000 - 11111111.11111111.11111110.00000000 
        organize_info(ip, cidr, 16, 2)
    if cidr >= 24:                           # 11111111.11111111.11111111.00000000 - 11111111.11111111.11111111.11111111
        organize_info(ip, cidr, 24, 3)


if __name__ == '__main__':
    print()
    get_subnet_and_ip_addr_count('192.168.10.17', cidr=8, subnet_mask=None)
    print()