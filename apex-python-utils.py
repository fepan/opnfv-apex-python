##############################################################################
# Copyright (c) 2016 Feng Pan (fpan@redhat.com)
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0
##############################################################################


import argparse
import sys
import apex
import logging
from jinja2 import Environment, FileSystemLoader

def parse_net_settings(settings_args):
    settings = apex.NetworkSettings(settings_args.path,
                                    settings_args.network_isolation)
    settings.dump_bash()


def find_ip(int_args):
    interface = apex.ip_utils.get_interface(int_args.interface,
                                      int_args.address_family)
    if interface:
        print(interface.ip)


def build_nic_template(nic_args):
    env = Environment(loader=FileSystemLoader('.'))
    template = env.get_template('controller.yaml.jinja2')
    print(template.render(enabled_networks=nic_args.enabled_networks,
                          external_net_type=nic_args.ext_net_type,
                          external_net_af=nic_args.address_family))


parser = argparse.ArgumentParser()
parser.add_argument('--DEBUG', action='store_true', default=False,
                    help="Turn on debug messages")
subparsers = parser.add_subparsers()

net_settings = subparsers.add_parser('parse_net_settings',
                                     help='Parse network settings file')
net_settings.add_argument('-n', '--path', default='network_settings.yaml',
                          help='path to network settings file')
net_settings.add_argument('-i', '--network_isolation', type=bool, default=True,
                          help='network isolation')
net_settings.set_defaults(func=parse_net_settings)

get_int_ip = subparsers.add_parser('find_ip',
                                   help='Find interface ip')
get_int_ip.add_argument('-i', '--interface', required=True,
                        help='Interface name')
get_int_ip.add_argument('-af', '--address_family', default=4, type=int,
                        choices=[4, 6],
                        help='IP Address family')
get_int_ip.set_defaults(func=find_ip)

nic_template = subparsers.add_parser('nic_template', help='Build NIC templates')
nic_template.add_argument('-n', '--enabled_networks', required=True, help='enabled network list')
nic_template.add_argument('-e', '--ext_net_type', default='interface', choices=['interface', 'br-ex'],
                          help='External network type')
nic_template.add_argument('-af', '--address_family', type=int, default=4, help='IP address family')
nic_template.set_defaults(func=build_nic_template)

args = parser.parse_args(sys.argv[1:])
if args.DEBUG:
    logging.basicConfig(level=logging.DEBUG)

if hasattr(args, 'func'):
    args.func(args)
else:
    parser.print_help()
    exit(1)
