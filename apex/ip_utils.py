##############################################################################
# Copyright (c) 2016 Feng Pan (fpan@redhat.com)
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0
##############################################################################


import ipaddress
import subprocess
import re
import logging


def get_ip_range(start_offset=None, count=None, end_offset=None,
                 cidr=None, interface=None):
    if cidr:
        if count and start_offset and not end_offset:
            start_index = start_offset
            end_index = start_offset + count
        elif count and end_offset and not start_offset:
            end_index = -1 - end_offset
            start_index = end_index - count
        elif start_offset and end_offset and not count:
            start_index = start_offset
            end_index = -1 - end_offset
        else:
            raise IPUtilsException("Argument error: must pass in exactly 2 of"
                                   "start_offset, end_offset and count")

        start_ip = cidr[1 + start_index]
        end_ip = cidr[end_index]
        network = cidr
    elif interface:
        network = interface.network
        number_of_addr = network.num_addresses
        if interface.ip < network[int(number_of_addr / 2)]:
            if count and start_offset and not end_offset:
                start_ip = interface.ip + start_offset
                end_ip = start_ip + count
            elif count and end_offset and not start_offset:
                end_ip = network[-1 - end_offset]
                start_ip = end_ip - count
            elif start_offset and end_offset and not count:
                start_ip = interface.ip + start_offset
                end_ip = network[-1 - end_offset]
            else:
                raise IPUtilsException(
                    "Argument error: must pass in exactly 2 of"
                    "start_offset, end_offset and count")
        else:
            if count and start_offset and not end_offset:
                start_ip = network[1 + start_offset]
                end_ip = start_ip + count
            elif count and end_offset and not start_offset:
                end_ip = interface.ip - end_offset
                start_ip = end_ip - count
            elif start_offset and end_offset and not count:
                start_ip = network[1 + start_offset]
                end_ip = interface.ip - end_offset
            else:
                raise IPUtilsException(
                    "Argument error: must pass in exactly 2 of"
                    "start_offset, end_offset and count")

    else:
        raise IPUtilsException("Must pass in cidr or interface to generate"
                               "ip range")

    range_result = validate_ip_range(start_ip, end_ip, network)
    if range_result == 0:
        ip_range = "{},{}".format(start_ip, end_ip)
        return ip_range
    else:
        raise IPUtilsException(range_result)


def get_ip(offset, cidr=None, interface=None):
    if cidr:
        ip = cidr[0 + offset]
        network = cidr
    elif interface:
        ip = interface.ip + offset
        network = interface.network
    else:
        raise IPUtilsException("Must pass in cidr or interface to generate IP")

    if ip not in network:
        raise IPUtilsException("IP {} not in network {}".format(ip, network))
    else:
        return str(ip)


def generate_ip_range(args):
    """
    Generate IP range in string format for given CIDR.
    This function works for both IPv4 and IPv6.

    args is expected to contain the following members:
    CIDR: any valid CIDR representation.
    start_position: starting index, default to first address in subnet (1)
    end_position:  ending index, default to last address in subnet (-1)

    Returns IP range in string format. A single IP is returned if start and
    end IPs are identical.
    """
    cidr = ipaddress.ip_network(args.CIDR)
    (start_index, end_index) = (args.start_position, args.end_position)
    if cidr[start_index] == cidr[end_index]:
        return str(cidr[start_index])
    else:
        return ','.join(sorted([str(cidr[start_index]), str(cidr[end_index])]))


def get_interface(nic, address_family=4):
    """Returns interface object for a given NIC name in the system"""
    if not nic.strip():
        logging.error("empty nic name specified")
        return None
    output = subprocess.getoutput("ip -{} addr show {} scope global"
                                  .format(address_family, nic))
    if address_family == 4:
        pattern = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}")
    elif address_family == 6:
        pattern = re.compile("([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}/\d{1,3}")
    else:
        raise IPUtilsException("Invalid address family: {}"
                               .format(address_family))
    match = re.search(pattern, output)
    if match:
        logging.info("found interface {} ip: {}".format(nic, match.group()))
        return ipaddress.ip_interface(match.group())
    else:
        logging.info("interface ip not found! ip address output:\n{}"
                     .format(output))
        return None


def find_gateway(interface):
    """Validate gateway on the system"""

    address_family = interface.version
    output = subprocess.getoutput("ip -{} route".format(address_family))

    pattern = re.compile("default\s+via\s+(\S+)\s+")
    match = re.search(pattern, output)

    if match:
        gateway_ip = match.group(1)
        reverse_route_output = subprocess.getoutput("ip route get {}"
                                                    .format(gateway_ip))
        pattern = re.compile("{}.+src\s+{}".format(gateway_ip, interface.ip))
        if not re.search(pattern, reverse_route_output):
            logging.warning("Default route doesn't match iterface specified: {}"
                            .format(reverse_route_output))
            return None
        else:
            return gateway_ip
    else:
        logging.warning("Can't find gateway address on system")
        return None


def validate_ip_range(start_ip, end_ip, cidr):
    ip_range = "{},{}".format(start_ip, end_ip)
    if end_ip <= start_ip:
        return ("IP range {} is invalid: end_ip should be greater than starting"
                " ip".format(ip_range))
    if start_ip not in ipaddress.ip_network(cidr):
        return 'start_ip {} is not in network {}'.format(start_ip, cidr)
    if end_ip not in ipaddress.ip_network(cidr):
        return 'end_ip {} is not in network {}'.format(end_ip, cidr)

    return 0


class IPUtilsException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value
