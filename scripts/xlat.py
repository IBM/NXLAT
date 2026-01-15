#!/usr/libexec/platform-python
# Copyright (C) 2025-2026 IBM Corporation.

import argparse
import dns.zone
import dns.rdataclass
import dns.rdatatype
import dns.ipv6
import netaddr
import os
import subprocess
import sys
import time
import yaml

script_dir = '{}'.format(str(os.path.dirname(os.path.realpath(__file__))))
sys.path += [script_dir, '.']

MODULE = 'jool_siit'
JOOL = '/usr/local/bin/jool_siit'

class CIDR4:
    _addr: netaddr.IPAddress
    def __init__(self, cidr: str):
        try:
            self._addr = netaddr.IPNetwork(cidr).ipv4()
        except netaddr.AddrFormatError as ex:
            print('invalid IPv4 CIDR: {}'.format(repr(ex)))
        except netaddr.AddrConversionError as ex:
            print('invalid IPv4 CIDR: {}'.format(repr(ex)))
        except ValueError as ex:
            print('invalid IPv4 CIDR: {}'.format(repr(ex)))
    def address(self) -> netaddr.IPAddress:
        return self._addr.ip
    def netmask(self) -> netaddr.IPAddress:
        return self._addr.netmask
    def prefixlen(self) -> int:
        return self._addr.prefixlen
    def cidr(self) -> str:
        return str(self._addr)

class CIDR6:
    _addr: netaddr.IPAddress
    def __init__(self, cidr: str):
        try:
            self._addr = netaddr.IPNetwork(cidr).ipv6()
        except netaddr.AddrFormatError as ex:
            print('invalid IPv6 CIDR: {}'.format(repr(ex)))
        except netaddr.AddrConversionError as ex:
            print('invalid IPv6 CIDR: {}'.format(repr(ex)))
        except ValueError as ex:
            print('invalid IPv6 CIDR: {}'.format(repr(ex)))
    def address(self) -> netaddr.IPAddress:
        return self._addr.ip
    def netmask(self) -> netaddr.IPAddress:
        return self._addr.netmask
    def prefixlen(self) -> int:
        return self._addr.prefixlen
    def cidr(self) -> str:
        return str(self._addr)

class HostConfig:
    _port: str
    _mtu: int
    _addr4: CIDR4
    _addr6: CIDR6
    _gw4: netaddr.IPAddress
    _gw6: netaddr.IPAddress
    def __init__(self, port: str, mtu: int, ip4: str, gw4: str, ip6: str, gw6: str):
        self._port = port
        self._mtu = mtu
        self._addr4 = CIDR4(ip4)
        self._gw4 = netaddr.IPAddress(gw4).ipv4()
        self._addr6 = CIDR6(ip6)
        self._gw6 = netaddr.IPAddress(gw6).ipv6()
        
    def port(self) -> str:
        return self._port
    def port_mtu(self) -> int:
        return self._mtu
    def ipv4_address(self) -> netaddr.IPAddress:
        return self._addr4.address()
    def ipv4_netmask(self) -> netaddr.IPAddress:
        return self._addr4.netmask()
    def ipv4_prefixlen(self):
        return self._addr4.prefixlen()
    def ipv4_cidr(self) -> str:
        return self._addr4.cidr()
    def ipv4_gateway(self) -> netaddr.IPAddress:
        return self._gw4
    def ipv6_address(self) -> netaddr.IPAddress:
        return self._addr6.address()
    def ipv6_netmask(self) -> netaddr.IPAddress:
        return self._addr6.netmask()
    def ipv6_prefixlen(self):
        return self._addr6.prefixlen()
    def ipv6_cidr(self) -> str:
        return self._addr6.cidr()
    def ipv6_gateway(self) -> netaddr.IPAddress:
        return self._gw6

class ClientConfig:
    _ipv4: netaddr.IPNetwork
    _ipv6 = [] 
    _protocol: str
    _svc = [] 
    def __init__(self, ipv4net: str, ipv6nets: [], protocol: str, ports: []):
        try:
            self._ipv4 = netaddr.IPNetwork(ipv4net).ipv4()
            for ip6 in ipv6nets:
                ip6n = netaddr.IPNetwork(ip6).ipv6()
                self._ipv6.append(ip6n)
            self._protocol = protocol
            for p in ports:
                self._svc.append(p)
        except netaddr.AddrFormatError as ex:
            print('AddrFormatError: {}'.format(repr(ex)))
        except netaddr.AddrConversionError as ex:
            print('AddrFormatError: {}'.format(repr(ex)))
        except ValueError as ex:
            print('ValueError: {}'.format(repr(ex)))
        #end try
    def ipv4_subnet(self) -> netaddr.IPNetwork:
        return self._ipv4
    def ipv6_subnets(self): 
        return self._ipv6
    def protocol(self) -> str:
        return self._protocol
    def svc_ports(self): 
        return self._svc

class ServerConfig:
    _protocol: str
    _svc_ports = [] 
    def __init__(self, protocol: str, svc_ports: []):
        self._protocol = protocol
        for svc in svc_ports:
            self._svc_ports.append(svc)
        #end for
    def protocol(self) -> str:
        return self._protocol
    def svc_ports(self): 
        return self._svc_ports

class SIITConfig:
    name: str
    vport_in: str
    vport_in_peer: str
    vport_out: str
    vport_out_peer: str
    _ipv4addr: CIDR4
    _ipv4gw: netaddr.IPAddress
    _ipv6addr: CIDR6
    _ipv6gw: netaddr.IPAddress
    
    def __init__(self, \
		 name: str, \
		 vport_in: str, \
		 vport_in_peer: str, \
		 vport_out: str, \
		 vport_out_peer: str, \
		 ipv4addr: str, \
		 ipv4gw: str, \
		 ipv6addr: str, \
		 ipv6gw: str):
        self.name = name
        self.vport_in = vport_in
        self.vport_in_peer = vport_in_peer
        self.vport_out = vport_out
        self.vport_out_peer = vport_out_peer
        self._ipv4addr = CIDR4(ipv4addr)
        self._ipv4gw = netaddr.IPAddress(ipv4gw).ipv4()
        self._ipv6addr = CIDR6(ipv6addr)
        self._ipv6gw = netaddr.IPAddress(ipv6gw).ipv6()
    def ipv4_address(self) -> netaddr.IPAddress:
        return self._ipv4addr.address()
    def ipv4_cidr(self) -> str:
        return self._ipv4addr.cidr()
    def ipv4_gateway(self) -> netaddr.IPAddress:
        return self._ipv4gw
    def ipv4_prefixlen(self) -> int:
        return self._ipv4addr.prefixlen()
    def ipv6_address(self) -> netaddr.IPAddress:
        return self._ipv6addr.address()
    def ipv6_cidr(self) -> str():
        return self._ipv6addr.cidr()
    def ipv6_gateway(self) -> netaddr.IPAddress:
        return self._ipv6gw
    def ipv6_prefixlen(self) -> int:
        return self._ipv6addr.prefixlen()
    
class Config:
    host: HostConfig
    client: ClientConfig
    server: ServerConfig
    siit: SIITConfig
    
    def __init__(self, conf: dict):
        self.host = HostConfig(conf['host']['port'], \
                               conf['host']['mtu'], \
                               conf['host']['ipv4addr'], \
                               conf['host']['ipv4gateway'], \
                               conf['host']['ipv6addr'], \
                               conf['host']['ipv6gateway'])

        self.client = ClientConfig(conf['clients']['ipv4-subnet'], \
                                   conf['clients']['ipv6-subnets'], \
                                   conf['clients']['protocol'], \
                                   conf['clients']['svc-ports'])

        self.server = ServerConfig(conf['servers']['protocol'], \
                                   conf['servers']['svc-ports'])
        
        self.siit = SIITConfig(conf['siit']['name'], \
                               conf['siit']['veth_in'], \
                               conf['siit']['veth_in_peer'], \
                               conf['siit']['veth_out'], \
                               conf['siit']['veth_out_peer'], \
                               conf['siit']['ipv4addr'], \
                               conf['siit']['ipv4gateway'], \
                               conf['siit']['ipv6addr'], \
                               conf['siit']['ipv6gateway'])
        
def execute(cmd: str, verbose=False) -> (int, str):
    if verbose:
        print(cmd)
    #end if
    ret = None
    try:
        ret = subprocess.check_output(cmd, shell=True)
    except subprocess.CalledProcessError as ex:
        return 1, ex.output.decode('utf-8')
    if ret:
        return 0, ret.decode()
    else:
        return 0, ''

def init_xlat(conf: Config) -> (int, str):
    '''
    Initialize SIIT XLAT by creating a namespace and configuring Jool SIIT module.
    '''
    # Enable IPv6 kernel forwarding
    cmd = 'sysctl -w net.ipv6.conf.all.disable_ipv6=0'
    ret, out = execute(cmd, args.v)
    if ret != 0:
        return ret, out
    #end if
    cmd = 'sysctl -w net.ipv6.conf.all.forwarding=1'
    ret, out = execute(cmd, args.v)
    if ret != 0:
        return ret, out
    #end if
    # Create SIIT namespace
    cmd = 'ip netns add {}'.format(conf.siit.name)
    ret, out = execute(cmd, args.v)
    if ret != 0:
        return ret, out
    #end if
    # configure IPv4 side of SIIT
    cmd = 'ip link add {} type veth peer {}'.format(conf.siit.vport_in, conf.siit.vport_in_peer)
    execute(cmd, args.v)
    cmd = 'ip link set {} up'.format(conf.siit.vport_in)
    execute(cmd, args.v)
    cmd = 'ip link set {} mtu {}'.format(conf.siit.vport_in, conf.host.port_mtu()-20)
    execute(cmd, args.v)
    cmd = 'ip addr add {}/{} dev {}'.format(conf.siit.ipv4_gateway(), conf.siit.ipv4_prefixlen(), conf.siit.vport_in)
    ret, out = execute(cmd, args.v)
    if ret != 0:
        return ret, out
    #end if
    cmd = 'ip link set {} netns {}'.format(conf.siit.vport_in_peer, conf.siit.name)
    execute(cmd, args.v)
    cmd = 'ip netns exec {} ip link set {} mtu {}'.format(conf.siit.name, conf.siit.vport_in_peer, conf.host.port_mtu()-20)
    execute(cmd, args.v)
    cmd = 'ip netns exec {} ip link set lo up'.format(conf.siit.name)
    execute(cmd, args.v)
    cmd = 'ip netns exec {} ip link set {} up'.format(conf.siit.name, conf.siit.vport_in_peer)
    execute(cmd, args.v)
    cmd = 'ip netns exec {} ip addr add {} dev {}'.format(conf.siit.name, conf.siit.ipv4_cidr(), conf.siit.vport_in_peer)
    ret, out = execute(cmd, args.v)
    if ret != 0:
        return ret, out
    #end if
    # IPv4 route to HOST IPv4 address
    cmd = 'ip netns exec {} ip route add {} via {}'.format(conf.siit.name, conf.host.ipv4_address(), conf.siit.ipv4_gateway())
    execute(cmd, args.v)
    # configure IPv6 side of SIIT
    cmd = 'ip link add {} type veth peer {}'.format(conf.siit.vport_out, conf.siit.vport_out_peer)
    execute(cmd, args.v)
    cmd = 'ip link set {} up'.format(conf.siit.vport_out)
    execute(cmd, args.v)
    cmd = 'ip link set {} mtu {}'.format(conf.siit.vport_out, conf.host.port_mtu())
    execute(cmd, args.v)
    cmd = 'ip addr add {}/{} dev {}'.format(conf.siit.ipv6_gateway(), conf.siit.ipv6_prefixlen(), conf.siit.vport_out)
    ret, out = execute(cmd, args.v)
    if ret != 0:
        return ret, out
    #end if
    cmd = 'ip link set {} netns {}'.format(conf.siit.vport_out_peer, conf.siit.name)
    execute(cmd, args.v)
    cmd = 'ip netns exec {} ip link set lo up'.format(conf.siit.name)
    execute(cmd, args.v)
    cmd = 'ip netns exec {} ip link set {} mtu {}'.format(conf.siit.name, conf.siit.vport_out_peer, conf.host.port_mtu())
    execute(cmd, args.v)
    cmd = 'ip netns exec {} ip link set {} up'.format(conf.siit.name, conf.siit.vport_out_peer)
    execute(cmd, args.v)
    cmd = 'ip netns exec {} ip addr add {} dev {}'.format(conf.siit.name, conf.siit.ipv6_cidr(), conf.siit.vport_out_peer)
    ret, out = execute(cmd, args.v)
    if ret != 0:
        return ret, out
    #end if
    # Add routes to client IPv6 subnets
    for snet in conf.client.ipv6_subnets():
        cmd = 'ip netns exec {} ip route add {} via {}'.format(conf.siit.name, snet, conf.siit.ipv6_gateway())
        execute(cmd, args.v)
    #end for
    
    # On the HOST default namespace
    # add IPv4 route to clients via synthetic IPv4 destinations
    cmd = 'ip route add {} via {} src {}'.format(conf.client.ipv4_subnet(), conf.siit.ipv4_address(), conf.host.ipv4_address())
    execute(cmd, args.v)
    #end for
    # Configure NAT rules to steer traffic into the namespace by DNATing to private IPv6 address
    for port in conf.server.svc_ports():
        # DNAT: ip6tables NAT rule to forward traffic to SIIT
        cmd = 'ip6tables -t nat -A PREROUTING -i {} -p {} -d {} --dport {} -j DNAT --to-destination {}'.format(conf.host.port(), conf.server.protocol(), conf.host.ipv6_address(), port, conf.siit.ipv6_address())
        execute(cmd, args.v)
    #end if
    # Configure SNAT to set public IPv6 IP for outgoing packets
    for port in conf.client.svc_ports():
        # SNAT: ip6tables rules for return traffic from external services
        cmd = 'ip6tables -t nat -A POSTROUTING -o {} -p {} -s {} --dport {} -j SNAT --to-source {}'.format(conf.host.port(), conf.server.protocol(), conf.siit.ipv6_address(), port, conf.host.ipv6_address())
        execute(cmd, args.v)
    #end for
    #Load jool_siit module
    cmd = 'modprobe {}'.format(MODULE)
    ret, out = execute(cmd, args.v)
    if ret != 0:
        return ret, out
    #end if
    # Create jool SIIT instance
    cmd = 'ip netns exec {} {} instance add default --iptables'.format(conf.siit.name, JOOL)
    ret, out = execute(cmd, args.v)
    if ret != 0:
        return ret, out
    #end if
    # Add EAMT rule for HDFS destination IPv4 address <-> IPv6 address
    cmd = 'ip netns exec {} {} eamt add {} {}'.format(conf.siit.name, JOOL, conf.siit.ipv6_address(), conf.host.ipv4_address())
    ret, out = execute(cmd, args.v)
    if ret != 0:
        return ret, out
    #end if
    # Add EAMT rule for local IPv4 GW address to IPv6 GW address
    cmd = 'ip netns exec {} {} eamt add {} {}'.format(conf.siit.name, JOOL, conf.siit.ipv6_gateway(), conf.siit.ipv4_gateway())
    ret, out = execute(cmd, args.v)
    if ret != 0:
        return ret, out
    #end if
    # Add iptables filtering rules
    for port in conf.server.svc_ports():
        # ip6tables rules for incoming traffic from HDFS clients
        cmd = 'ip netns exec {} ip6tables -t mangle -A PREROUTING -i {} -p {} --dport {} -j JOOL_SIIT --instance default'.format(conf.siit.name, conf.siit.vport_out_peer, conf.server.protocol(), port)
        ret, out = execute(cmd, args.v)
        if ret != 0:
            return ret, out
        #end if
    #end for
    # iptables rules for outgoing traffic to external services
    cmd = 'ip netns exec {} iptables -t mangle -A PREROUTING -i {} -j JOOL_SIIT --instance default'.format(conf.siit.name, conf.siit.vport_in_peer)
    ret, out = execute(cmd, args.v)
    if ret != 0:
        return ret, out  
    #end if
    # ip6tables rules for outgoing traffic to external services 
    for port in conf.client.svc_ports():
        # ip6tables rules for return traffic from external services
        cmd = 'ip netns exec {} ip6tables  -t mangle -A PREROUTING -i {} -p {} --sport {} -j JOOL_SIIT --instance default'.format(conf.siit.name, conf.siit.vport_out_peer, conf.client.protocol(), port)
        ret, out = execute(cmd, args.v)
        if ret != 0:
            return ret, out
        #end if
    #end for
    return 0, 'DONE!'
 
def deinit_xlat(conf):
    cmd = 'ip netns exec {} {} eamt flush'.format(conf.siit.name, JOOL)
    execute(cmd, args.v)
    cmd = 'ip netns exec {} {} instance flush'.format(conf.siit.name, JOOL)
    execute(cmd, args.v)
    cmd = 'ip netns del {}'.format(conf.siit.name)
    execute(cmd, args.v)
    time.sleep(5) # wait 5 seconds before trying to uload Jool kernel module 
    cmd = 'modprobe -r {}'.format(MODULE)
    execute(cmd, args.v)
    # delete ip6tables NAT rules
    for port in conf.server.svc_ports():
        # DNAT
        cmd = 'ip6tables -t nat -D PREROUTING -i {} -p {} -d {} --dport {} -j DNAT --to-destination {}'.format(conf.host.port(), conf.server.protocol(), conf.host.ipv6_address(), port, conf.siit.ipv6_address())
        execute(cmd, args.v)
    #end for
    for port in conf.client.svc_ports():
        # SNAT
        cmd = 'ip6tables -t nat -D POSTROUTING -o {} -p {} -s {} --dport {} -j SNAT --to-source {}'.format(conf.host.port(), conf.client.protocol(), conf.siit.ipv6_address(), port, conf.host.ipv6_address())
        execute(cmd, args.v)
    #end for

def add_eamt_entry(conf: Config, ipv6: str, ipv4: str) -> (int, str):
    valid, error = check_subnet_member(ipv4, conf.client.ipv4_subnet())
    if valid:
        cmd = 'ip netns exec {} {} eamt add {} {}'.format(conf.siit.name, JOOL, ipv6, ipv4)
        return execute(cmd, args.v)
    else:
        return 1, error
    #end if

def del_eamt_entry(ns: str, ipv6: str, ipv4: str) -> (int, str):
    cmd = 'ip netns exec {} {} eamt remove {} {}'.format(conf.siit.name, JOOL, ipv6, ipv4)
    return execute(cmd, args.v)

def check_ipv4_addr(ip: str) -> (bool, str):
    try:
        netaddr.IPAddress(ip).ipv4()
        return True, ''
    except netaddr.AddrFormatError as ex:
        return False, str(ex)
    except netaddr.AddrConversionError as ex:
        return False, str(ex)
    #end try

def check_ipv6_addr(ip: str) -> (bool, str):
    try:
        netaddr.IPAddress(ip).ipv6()
        return True, ''
    except netaddr.AddrFormatError as ex:
        return False, str(ex)
    except netaddr.AddrConversionError as ex:
        return False, str(ex)
    #end try

def check_subnet_member(ip: str, subnet: str) -> (bool, str):
    try:
        addr = netaddr.IPAddress(ip)
        network = netaddr.IPNetwork(subnet)
        if addr in network:
            return True, None
        else:
            return False, 'Address {} does not belong to subnet {}'.format(ip, subnet)
        #end if
    except ValueError as ex:
        return False, 'Error parsing address: {}'.format(str(ex))
    #end try
    
def read_hosts_file(path: str) -> (dict, str):
    hosts = {}
    try:
        with open(path, 'r') as hostdb:
            for line in hostdb:
                line = line.strip()
                if len(line) == 0 or line.startswith('#') or is_localhost(line):
                    continue
                #end if
                tokens = line.split()
                if len(tokens) < 2:
                    continue
                #end if
                ret, err = check_ipv4_addr(tokens[0])
                if ret:
                    if tokens[1] in hosts:
                        hosts[tokens[1]]['ipv4'] = tokens[0]
                    else:
                        hosts[tokens[1]] = {'ipv4': tokens[0], 'ipv6': None}
                    #end if
                    continue
                #end if
                ret, err = check_ipv6_addr(tokens[0])
                if ret:
                    if tokens[1] in hosts:
                        hosts[tokens[1]]['ipv6'] = tokens[0]
                    else:
                        hosts[tokens[1]] = {'ipv4': None, 'ipv6': tokens[0]}
                    #end if
                #end if
            #end for
        #end with
    except FileNotFoundError:
        return None, 'Failed to locate hosts file: {}'.format(path)
    except OSError:
        return None, 'Failed to open hosts file: {}'.format(path)
    except Exception as err:
        return None, 'Unexpected error {} occured opening file: {}'.format(repr(err), path)
    #end try
    return hosts, None

def is_localhost(line: str) -> bool:
    addrs = line.split()
    localhosts = ['127.0.0.1', 'ff00::0', 'fe00::0', 'ff02::1', '::1']
    if addrs[0] in localhosts:
        return True
    #end if
    return False

# MAIN
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', help='Print configuration commands.', action='store_true', default=False)
    subparser = parser.add_subparsers(dest='cmd', help='Available commands.')
    initparser = subparser.add_parser('init', help='Initialize XLAT.')
    initparser.add_argument('-conf', help='XLAT YAML configuration file', default='/etc/xlat/xlat.yaml')
    deinitparser = subparser.add_parser('deinit', help='Remove XLAT configurations.')
    deinitparser.add_argument('-conf', help='XLAT YAML configuration file.', default='/etc/xlat/xlat.yaml')
    addparser = subparser.add_parser('add', help='Add an EAMT entry.')
    addparser.add_argument('-ipv6', help='IPv6 address to be translated to an IPv4 address.')
    addparser.add_argument('-ipv4', help='IPv4 address to be translated to an IPv6 address.')
    addparser.add_argument('-conf', help='XLAT YAML configuration file.', default='/etc/xlat/xlat.yaml')
    delparser = subparser.add_parser('del', help='Delete an EAMT entry.')
    delparser.add_argument('-ipv6', help='IPv6 address to be translated to an IPv4 address.')
    delparser.add_argument('-ipv4', help='IPv4 address to be translated to an IPv6 address.')
    delparser.add_argument('-conf', help='XLAT YAML configuration file.', default='/etc/xlat/xlat.yaml')
    loadparser = subparser.add_parser('load', help='Configure Jool EAMT rules from a hosts file.')
    loadparser.add_argument('-conf', help='XLAT YAML configuration file.', default='/etc/xlat/xlat.yaml')
    loadparser.add_argument('-file', help='A hosts file listing hostnames with both IPv4 and IPv6 addresses.', default='/etc/hosts')
    listparser = subparser.add_parser('list', help='List Jool EAMT rules.')
    listparser.add_argument('-format', help='List format (tabular | csv).', default='tabular')
    listparser.add_argument('-filter', help='List iptables filter rules.', action='store_true', default=False)
    listparser.add_argument('-nat', help='List iptables DNAT/SNAT rules.', action='store_true', default=False)
    listparser.add_argument('-conf', help='XLAT YAML configuration file.', default='/etc/xlat/xlat.yaml')
    showparser = subparser.add_parser('show', help='Check if a Jool EAMT entry exists.')
    showparser.add_argument('-ipv4', help='IPv4 address.')
    showparser.add_argument('-ipv6', help='IPv6 address.')
    showparser.add_argument('-conf', help='XLAT YAML configuration file.', default='/etc/xlat/xlat.yaml')
    genhostsfile = subparser.add_parser('gen', help='Generate /etc/hosts with IPv4 and IPv6 addresses from bind9 Ipv6 zone file')
    genhostsfile.add_argument('-conf', help='XLAT YAML configuration file.', default='/etc/xlat/xlat.yaml')
    genhostsfile.add_argument('-v6zone', help='BIND9 IPv6 Zone file.')
    genhostsfile.add_argument('-domain', help='The fully-qualified domain name of the zone.')
    genhostsfile.add_argument('-v6host', help='IPv6 hosts file.')
    genhostsfile.add_argument('-hostsfile', default='/etc/hosts', help='Output hosts file with both IPv4 and IPv6 addresses.')
    args = parser.parse_args()
    if args.cmd is None:
        parser.print_help()
        sys.exit(1)
    #end if
    conf = None
    if args.conf is None:
        parser.print_help()
        sys.exit(1)
    #end if
    try:
        with open(args.conf, 'r') as cfg:
            data = yaml.safe_load(cfg)
            conf = Config(data)
        #end with
    except FileNotFoundError:
        print('Failed to find XLAT configuration file: {}'.format(args.conf))
        sys.exit(1)
    except OSError:
        print('Failed to open XLAT configuration file: {}'.format(args.conf))
        sys.exit(2)
    except Exception as err:
        print('Unexpected error {} occured opening XLAT configuration file: {}'.format(repr(err), args.conf))
        sys.exit(3)
    #end try
    if args.cmd == 'init':
        ret, err = init_xlat(conf) 
        if ret != 0:
            print('Failed to initialize XLAT, error: {}'.format(err))
            sys.exit(1)
        else:
            print(err)
        #end if
    elif args.cmd == 'deinit':
        deinit_xlat(conf)
    elif args.cmd == 'add':
        ipv6OK, _ = check_ipv6_addr(args.ipv6)
        ipv4OK, _ = check_ipv4_addr(args.ipv4)
        if ipv4OK and ipv6OK:
            ret, err = add_eamt_entry(conf, args.ipv6, args.ipv4)
            if ret != 0:
                print('Failed to add Jool EAMT entry: {}'.format(err))
                sys.exit(1)
            #end if
        else:
            print('Invalid IP addresses for an EAMT entry: {} <-> {}'.format(args.ipv6, args.ipv4))
            sys.exit(1)
        #end if
    elif args.cmd == 'del':
        ipv6OK, _ = check_ipv6_addr(args.ipv6)
        ipv4OK, _ = check_ipv4_addr(args.ipv4)
        if ipv4OK and ipv6OK:
            ret, err = del_eamt_entry(conf.siit.name, args.ipv6, args.ipv4)
            if ret != 0:
                print('Failed to delete Jool EAMT entry: {}'.format(err))
                sys.exit(1)
            #end if
        else:
            print('Invalid IP addresses for an EAMT entry: {} <-> {}'.format(args.ipv6, args.ipv4))
            sys.exit(1)
        #end if
    elif args.cmd == 'load':
        hosts, err = read_hosts_file(args.file)
        if err:
            print('Failed to read hosts file: {}'.format(err))
            sys.exit(1)
        #end if
        for _, addr in hosts.items():
            if addr['ipv6'] and addr['ipv4']:
                ret, err = add_eamt_entry(conf, addr['ipv6'], addr['ipv4'])
                if ret != 0:
                    print('Failed to add Jool EAMT entry: {}'.format(err))
                    # sys.exit(1)
                #end if
            #end if
        #end for
    elif args.cmd == 'list':
        if args.filter:
            res = ''
            cmd = 'ip netns exec {} iptables-save -t mangle -c | grep JOOL_SIIT'.format(conf.siit.name)
            ret, out = execute(cmd, args.v)
            if ret != 0:
                print('Failed to list Netfilter iptables rules: {}'.format(out))
                sys.exit(1)
            #end if
            res += out
            cmd = 'ip netns exec {} ip6tables-save -t mangle -c | grep JOOL_SIIT'.format(conf.siit.name)
            ret, out = execute(cmd, args.v)
            if ret != 0:
                print('Failed to list Netfilter iptables rules: {}'.format(out))
                sys.exit(1)
            #end if
            res += out
            print(res)
        elif args.nat:
            res = ''
            cmd = 'ip6tables-save -t nat -c | grep -e "--to-destination {}"'.format(conf.siit.ipv6_address())
            ret, out = execute(cmd, args.v)
            if ret == 0:
                res += out    
            #end if
            cmd = 'ip6tables-save -t nat -c | grep -e "--to-source {}"'.format(conf.host.ipv6_address())
            ret, out = execute(cmd, args.v)
            if ret == 0:
                res += out                
            #end if
            if res == '':
                print('No Netfilter rules found.')
            else:
                print(res)
            #end if
        else:
            if args.format == 'csv':
                cmd = 'ip netns exec {} {} eamt display --csv --no-headers'.format(conf.siit.name, JOOL)
                ret, out = execute(cmd, args.v)
                if ret != 0:
                    print('Failed to list Jool EAMT rules: {}'.format(out))
                else:
                    print(out)
                #end if
            else:
                cmd = 'ip netns exec {} {} eamt display'.format(conf.siit.name, JOOL)
                ret, out = execute(cmd, args.v)
                if ret != 0:
                    print('Failed to list Jool EAMT rules: {}'.format(out))
                else:
                    print(out)
                #end if
            #end if
        #end if
    elif args.cmd == 'show':
        if args.ipv4 is None and args.ipv6 is None:
            print('Missing both IPv4 and IPv6 address to check an EAMT entry with.')
            sys.exit(1)
        #end if
        if args.ipv4:
            ret, err = check_ipv4_addr(args.ipv4)
            if ret is False:
                print('Error parsing IPv4 address: {}'.format(args.ipv4))
                sys.exit(1)
            #end if
        #end if
        if args.ipv6:
            ret, err = check_ipv6_addr(args.ipv6)
            if ret is False:
                print('Error parsing IPv6 address: {}'.format(args.ipv6))
                sys.exit(1)
            #end if
        #end if
        cmd = 'ip netns exec {} {} eamt display --csv --no-headers'.format(conf.siit.name, JOOL)
        ret, out = execute(cmd, args.v)
        for line in out.splitlines():
            addrs = line.split(',')
            ipv4 = addrs[1].split('/')[0]
            ipv6 = addrs[0].split('/')[0]
            if args.ipv4 and ipv4 == args.ipv4:
                if args.ipv6:
                    if ipv6 == args.ipv6:
                        print('EAMT ENTRY {} <-> {}'.format(args.ipv6, args.ipv4))
                    else:
                        print('NO EAMT ENTRY {} <-> {}'.format(args.ipv6, args.ipv4))
                    #end if
                else:
                    print('EAMT ENTRY {} <-> {}'.format(addrs[0], addrs[1]))
                #end if
                sys.exit(0)
            elif args.ipv6 and ipv6 == args.ipv6:
                if args.ipv4:
                    if ipv4 == args.ipv4:
                        print('EAMT ENTRY {} <-> {}'.format(args.ipv6, args.ipv4))
                        break
                    else:
                        print('NO EAMT ENRTY {} <-> {}'.format(args.ipv6, args.ipv4))
                    #end if
                else:
                    print('EAMT ENTRY {} <-> {}'.format(addrs[0], addrs[1]))
                #end if
                sys.exit(0)
            #end if
        #end for
        print('NO EAMT ENRTY {} <-> {}'.format(args.ipv6, args.ipv4))
    elif args.cmd == 'gen':
        try:
            with open(args.hostsfile, 'a') as fhosts:
                v4addrs = conf.client.ipv4_subnet().iter_hosts()
                if args.v6zone:
                    if args.domain is None:
                        print('Domain name is required for IPv6 Zone.')
                        sys.exit(1)
                    #end if
                    zone6 = dns.zone.from_file(args.v6zone, args.domain, relativize=True)
                    for name, node in zone6.nodes.items():
                        for rdataset in node.rdatasets:
                            if rdataset.rdtype == dns.rdatatype.AAAA:
                                for rdata in rdataset:
                                    fhosts.write('{} {}\n'.format(rdata, str(name) + '.' + args.domain))
                                    fhosts.write('{} {}\n'.format(next(v4addrs), str(name) + '.' + args.domain))
                                #end fpr
                            #end if
                        #end for
                    #end for
                elif args.v6host:
                    hosts = open(args.v6host, 'r')
                    for line in hosts.readlines():
                        if len(line.strip()) == 0 or line.startswith('#'):
                            continue
                        #end if
                        tokens = line.strip().split()
                        if netaddr.IPAddress(tokens[0]).version == 6:
                            fhosts.write('{} {}\n'.format(tokens[0], tokens[1]))
                            fhosts.write('{} {}\n'.format(next(v4addrs), tokens[1]))
                        #end if
                    #end for
                #end if
            #end with open()
        except netaddr.AddrFormatError as ex:
            print('IP address parsing error: {}'.format(repr(ex)))
            sys.exit(1)
        except netaddr.AddrConversionError as ex:
            print('IP address parsing error: {}'.format(repr(ex)))
            sys.exit(2)
        except FileNotFoundError as ex:
            print('File not found error: {}'.format(repr(ex)))
            sys.exit(3)
        except OSError as ex:
            print('Error encountered: {}'.format(repr(ex)))
            sys.exit(4)
        except Exception as ex:
            print('Exception: {}'.format(repr(ex)))
            sys.exit(5)
        #end try
    #end if
