from pyasn1.type import univ
from pyasn1_modules import rfc3779
from .config import ipv4addr, ipv4AddrRange, ipv6addr, ipv6AddrRange, ipaddrsConfig, asid, asidRange

def create_ipv4_address(prefix):
    address, prefix_len = prefix.split('/')
    # print(address, prefix_len)
    prefix_len = int(prefix_len)
    
    address_parts = address.split('.')
    address_bytes = bytes(int(part) for part in address_parts)
    
    
    total_bits = 32  
    used_bits = prefix_len  
    unused_bits = total_bits - used_bits
    
    address_bin = ''.join(format(byte, '08b') for byte in address_bytes)
    
    address_bin_prefix = address_bin[:prefix_len]
    
    bit_string = univ.BitString(binValue=address_bin_prefix)
    return bit_string

def expand_ipv6_address(address):
    if '::' not in address:
        return ':'.join(f"{int(x, 16):04x}" for x in address.split(':'))

    before_colon, _, after_colon = address.partition('::')

    before_parts = before_colon.split(':') if before_colon else []
    after_parts = after_colon.split(':') if after_colon else []

    zeros_to_add = 8 - len(before_parts) - len(after_parts)

    full_parts = (
        before_parts +
        ['0'] * zeros_to_add +
        after_parts
    )

    expanded_address = ':'.join(f"{int(x, 16):04x}" for x in full_parts)
    return expanded_address

def create_ipv6_address(prefix):
    address, prefix_len = prefix.split('/')
    prefix_len = int(prefix_len)
    
    full_address = expand_ipv6_address(address)
    
    binary_string = ''.join(format(int(part, 16), '016b') for part in full_address.split(':'))
    
    binary_prefix = binary_string[:prefix_len]
    
    bit_string = univ.BitString(binValue=binary_prefix)
    return bit_string

def create_ipv6_addressPrefix(address_prefix):
    ip_or_range = rfc3779.IPAddressOrRange()
    ip_or_range['addressPrefix'] = create_ipv6_address(address_prefix)
    return ip_or_range

def create_ipv6_addressRange(addr_min, addr_max):
    ip_or_range = rfc3779.IPAddressOrRange()
    ip_range = rfc3779.IPAddressRange()
    ip_range['min'] = create_ipv6_address(addr_min)
    ip_range['max'] = create_ipv6_address(addr_max)
    ip_or_range['addressRange'] = ip_range
    return ip_or_range

def create_ipv6_address_choice(choices:list):
    ip_address_choice = rfc3779.IPAddressChoice()
    ip_address_choice['addressesOrRanges'] = univ.SequenceOf(componentType=rfc3779.IPAddressOrRange())

    for choice in choices:
        # ip_address_choice['addressesOrRanges'].append(create_ip_address_or_range(prefix, v4=v4))
        if isinstance(choice, ipv6addr):
            ip_address_choice['addressesOrRanges'].append(create_ipv6_addressPrefix(choice.ipv6_addr))
        elif isinstance(choice, ipv6AddrRange):
            ip_address_choice['addressesOrRanges'].append(create_ipv6_addressRange(choice.min, choice.max))
        else:
            print(choice)
            raise ValueError("Unknown ip address type")
            # exit("Unknown ip address type")
    return ip_address_choice

def create_ipv4_addressPrefix(address_prefix):
    ip_or_range = rfc3779.IPAddressOrRange()
    ip_or_range['addressPrefix'] = create_ipv4_address(address_prefix)
    return ip_or_range

def create_ipv4_addressRange(addr_min, addr_max):
    ip_or_range = rfc3779.IPAddressOrRange()
    ip_range = rfc3779.IPAddressRange()
    ip_range['min'] = create_ipv4_address(addr_min)
    ip_range['max'] = create_ipv4_address(addr_max)
    ip_or_range['addressRange'] = ip_range
    return ip_or_range

def create_ipv4_address_choice(choices:list):
    ip_address_choice = rfc3779.IPAddressChoice()
    ip_address_choice['addressesOrRanges'] = univ.SequenceOf(componentType=rfc3779.IPAddressOrRange())

    for choice in choices:
        # ip_address_choice['addressesOrRanges'].append(create_ip_address_or_range(prefix, v4=v4))
        if isinstance(choice, ipv4addr):
            ip_address_choice['addressesOrRanges'].append(create_ipv4_addressPrefix(choice.ipv4_addr))
        elif isinstance(choice, ipv4AddrRange):
            ip_address_choice['addressesOrRanges'].append(create_ipv4_addressRange(choice.min, choice.max))
        else:
            # exit("Unknown ip address type")
            raise ValueError("Unknown ip address type")
    return ip_address_choice
