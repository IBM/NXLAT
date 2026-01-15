% xlat(1) Version 1.0 | A Host-Based IPv4/IPv6 Translation Tool
% Abdul Alim, Anand Singh, and Bengi Karacali. IBM Research. Contact: malim@us.ibm.com
% November 25, 2025 

# NAME
xlat - A host-based IPv4/IPv6 translation tool using Jool kernel module.  
 
# SYNOPSIS

**xlat** \[**-h**|**--help**] \[**-v**] \[**command**] \[*parameters*]

# OPTIONS
-h, \--help
:   Show usage message.

-v
: Verbose mode to print the configuration commands (iproute2, iptables/ip6tables, jool_siit) executed.

**command**
: One of the following commands.

**parameters**
: Command-specific list of parameters.

**commands**:

**init** \[**-h**|**--help**] \[**-conf** *CONF*]
: Sets up XLAT environment using using the configuration file (*CONF*, default **/etc/xlat/xlat.yaml**). 

**deinit** \[**-h**|**--help**] \[**-conf** *CONF*]
: Removes XLAT related configuration from the system including ip/ip6tables and Jool EAMT rules using
the configuration file *CONF*, default **/etc/xlat/xlat.yaml**.

**load** \[**-h**|**--help**] \[**-conf** *CONF*] \[**-file** *FILE*]
: Configures Jool EAMT entries from the hosts file *FILE*, default **/etc/hosts** and configuration
file *CONF*, default **/etc/xlat/xlat.yaml**.  

**add** \[**-h**|**--help**] \[**-conf** *CONF*] **-ipv4** *IPv4* **-ipv6** *IPv6*
: Adds a Jool SIIT EAMT entry that maps an *IPv4* address to an *IPv6* address using configuration
file *CONF*, default **/etc/xlat/xlat.yaml**.

**del** \[**-h**|**--help**] \[**-conf** *CONF*] **-ipv4** *IPv4* **-ipv6** *IPv6*
: Removes a Jool SIIT EAMT entry that maps an *IPv4* address to an *IPv6* address using configuration
file *CONF*, default **/etc/xlat/xlat.yaml**.

**show** \[**-h**|**--help**] \[**-conf** *CONF*] \[**-ipv4** *IPv4*] \[**-ipv6** *IPv6*]
: Checks if a Jool SIIT EAMT entry exists using configuration file *CONF*, default **/etc/xlat/xlat.yaml**.
Either **-ipv4** or **-ipv6** parameter is required.

**list**  \[**-h**|**--help**] \[**-conf** *CONF*] \[**-format** *csv*] \[**-nat|-filter**]
: Prints Jool SIIT EAM table in tabular format by default and in CSV format if **-format csv**
is specified. To list NAT (both DNAT and SNAT ip6tables rules) specify the **-nat** flag and
specify the **-filter** flag to list ip/ip6tables filter rules. Note that **-nat** and **-filter**
flags are mutually exclusive and **-format csv** is only useful to list EAMT rules and not 
applicable to **-nat** or **-filter** options.

**gen**  \[**-h**|**--help**] \[**-conf** *CONF*] \[**-v6zone** *zonefile*] \[**-v6hosts** *hostsfile*] \[**-domain** *domainname*] \[**-hostsfile** *output*]
: Generate the */etc/hosts* file with both IPv4 and IPv6 addresses from either from an IPv6 BIND9 authoritative forward zone file or from an IPv6 only /etc/hosts file. It assign IPv4 addresses to IPv6 hosts (IPv6 addresses come from the input file) from the XLAT client IPv4 subnet configured in XLAT config file.

# DESCRIPTION

A host-based IPv4/IPv6 translation on the servers listening on an IPv4 address on a dual-stack
server physically connected to an IPv6 network. It runs Jool SIIT kernel module inside
a network namespace (SIIT). IPTABLES DNAT rules are used to redirect incoming traffic to 
Jool SIIT module for IPv6 to IPv4 translation, which uses private IPv6 and IPv4 addresses,
and SNAT rules to set server's public IPv6 address as the source address to outgoing traffic.
It uses Jool EAMT rules to translate IPv6 addresses into IPv4 addresses and vice-versa.

## Installation
RHEL 8.10 (Oopta) RPM package (nxlat-1.0-YYYYMMDD.el8.x86_64.rpm) is built by compiling Jool
source code (jool-4.1.14.tar.gz) downloaded from https://www.jool.mx/en/download.html. A Python
script (xlat.py) is added to the package to help configure and manage the servers for IPv6/IPv4
translation. It depends on Python 3, iproute2, and iptables utilities. To install this package use
any RedHat package manager tool such as yum, e.g., sudo yum install nxlat-1.0-YYYYMMDD.el8.x86_64.rpm.
It installs Jool kernel modules and Jool userspace utilities along with the XLAT script.

## Configuration
The xlat utility uses a configuration file in YAML format. The package comes with an example
configuration file, which is installed in /ect/xlat directory, default configuration file is
/ect/xlat/xlat.yaml. The configuration file contains four sections: host, servers, clients,
and siit. The `host` section specifies the server's interface name via which the server communicates
with the clients. We assume that servers are dual-stack servers, i.e., they use both IPv4 and
IPv6 for communications. So the interface is configured with both IPv4 and IPv6 addresses (routable)
and the services run on IPv4. The `host` section of the configuration file also specifies the
port MTU and IPv4 and IPv6 addresses along with corresponding gateway addresses as shown below:
```
host:
  port: enp7s0
  mtu: 9000
  ipv4addr: '192.168.100.104/24'
  ipv4gateway: '192.168.100.1'
  ipv6addr: '2001:db8:100::104/64'
  ipv6gateway: '2001:db8:100::1'
```

The `clients` section of the configuration file lists the IPv6 subnets of the clients, IPv6 subnets
of the services running on the client network. We assume that all these subnets are reachable via
the same IPv6 gateway address specified in the `host` section. In addition to IPv6 subnets, `clients`
section also specifies a private IPv4 subnet from which IPv4 addresses will be allocated to the clients
and other IPv6 servers on the client network. These private IPv4 addresses will be used as the source
addresses in translated IPv4 packets. Note that the server's IPv4 address will be used as the destination
address in the translated IPv4 packets. Furthermore, the `clients` section specifies the protocol (TCP)
and port numbers to reach the services on the client network as shown below.
```
clients:
  ipv6-subnets: ['2001:db8:200::/64']
  ipv4-subnet: '172.31.0.0/16'
  protocol: tcp
  svc-ports: [1234, 2345]
```

The `servers` section of the configuration file is used to specify the protocol and ports of of the services
on this server as shown below:
```
servers:
  protocol: tcp
  svc-ports: [3456, 4567]
```

Finally, the `siit` section is used to specify XLAT implementation internal parameters and is not related
to the clients or the servers and should be left as they come with the package. Internal XLAT parameters
include the name of the Linux network namespace to run Jool in, Linux veth pair names to connect the namespace
to the host IPv6 network, Linux veth pair names to connect the namespace to the host IPv4 network, two private
IPv6 and two private IPv4 addresses to configure on these virtual ports, where the *ipvXaddrs* are configured
inside the namespace and **ipvXgateways** are configured outside the namespace.
```
siit:
  name: SIIT
  veth_out: siit6
  veth_out_peer: siit6p
  veth_in: siit4
  veth_in_peer: siit4p
  ipv4addr: '192.168.255.1/30'
  ipv4gateway: '192.168.255.2'
  ipv6addr: 'fd00:ab:cd::1/64'
  ipv6gateway: 'fd00:ab:cd::2'
```

## EXAMPLES
Once a configuration is created with correct configuration parameters, initialize the XLAT SIIT
by running xlat.py init as follows.
```
# sudo /usr/local/bin/xlat.py init -conf xlat.yaml
```
Note that `xlat` by default uses /etc/xlat/xlat.yaml as its configuration file, so you do not have
to specify -conf every time you run xlat tool. Besides, you could use the verbose (-v) option as
xlat.py -v init to see how it configures Jool SIIT. If the configurations are correct, init should
finish with `DONE!' message, which indicates that the XLAT setup is complete.
```
# xlat.py init
DONE!
```

You could run the `xlat list` command to see the Jool translation rules as follows:
```
# xlat.py list
+---------------------------------------------+--------------------+
|                                 IPv6 Prefix |        IPv4 Prefix |
+---------------------------------------------+--------------------+
|                           fd00:ab:cd::2/128 |   192.168.255.2/32 |
|                           fd00:ab:cd::1/128 | 192.168.100.104/32 |
+---------------------------------------------+--------------------+
```
You could also run `xlat list -nat` command to see the iptables NAT rules that configured
on the system as shown below:
```
# xlat.py list -nat
[0:0] -A PREROUTING -i enp7s0 -p tcp -m tcp --dport 3456 -j DNAT --to-destination fd00:ab:cd::1
[0:0] -A PREROUTING -i enp7s0 -p tcp -m tcp --sport 4567 -j DNAT --to-destination fd00:ab:cd::1
[0:0] -A POSTROUTING -o enp7s0 -p tcp -m tcp --dport 1234 -j SNAT --to-source 2001:db8:100::104
[0:0] -A POSTROUTING -o enp7s0 -p tcp -m tcp --dport 2345 -j SNAT --to-source 2001:db8:100::104
```

Finally, you run `xlat list -filter` command to see the iptables rules (mangle) that are
configured for Jool SIIT translation:
```
# xlat.py list -filter
Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source     destination         
    0     0 JOOL_SIIT  all  --  siit4p *       0.0.0.0/0  0.0.0.0/0    instance:default
Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out  source  destination         
    0     0 JOOL_SIIT  tcp      siit6p *    ::/0    ::/0         tcp dpt:3456 instance:default
    0     0 JOOL_SIIT  tcp      siit6p *    ::/0    ::/0         tcp dpt:4566 instance:default
    0     0 JOOL_SIIT  tcp      siit6p *    ::/0    ::/0         tcp spt:1234 instance:default
    0     0 JOOL_SIIT  tcp      siit6p *    ::/0    ::/0         tcp spt:2345 instance:default
```

## Configuring Explicit Address Mapping Table (EAMT) Entries
To add an EAMT entry for a given IPv6 and IPv4 address pair, run xlat.py add command as follows:
```
# xlat.py add -ipv6 2001:db8:200::102 -ipv4 172.31.0.102
```
and the updated Jool EAMT with a new entry is shown below:
```
# xlat.py list
+---------------------------------------------+--------------------+
|                                 IPv6 Prefix |        IPv4 Prefix |
+---------------------------------------------+--------------------+
|                       2001:db8:200::102/128 |    172.31.0.102/32 |
|                           fd00:ab:cd::2/128 |   192.168.255.2/32 |
|                           fd00:ab:cd::1/128 | 192.168.100.104/32 |
+---------------------------------------------+--------------------+
```

Note that the IPv6 address must come from the clients' IPv6 subnets and the IPv4 address must
be from the clients' IPv4 subnet.

You could remove an EAMT entry by running `xlat del` command as follow:
```
# xlat.py del -ipv6 2001:db8:200::102 -ipv4 172.31.0.102
```
and the updated Jool EAMT is shown below:
```
# xlat.py list
+---------------------------------------------+--------------------+
|                                 IPv6 Prefix |        IPv4 Prefix |
+---------------------------------------------+--------------------+
|                           fd00:ab:cd::2/128 |   192.168.255.2/32 |
|                           fd00:ab:cd::1/128 | 192.168.100.104/32 |
+---------------------------------------------+--------------------+
```

Since the solution requires DNS name and address resolution, we use EAMT rules for each IPv4/IPv6 address
translation instead of letting Jool to automatically generating an IPv4/IPv6 mapping from a given pool.
For DNS name/address resolution, we use `dnsmasq` with `/etc/hosts` file for simplicity. So we have to
populate the `/etc/hosts` files on each servers with all the clients' names and IPv6 addresses as well as
allocating a private IPv4 address from the clients IPv4 subnet configured in the xlat configuration file. Once
the `/etc/hosts` file has been populated with all the clients and external servers names and IPv4 and IPv6
addresses, you could configure Jool EAMT rules automatically by using `xlat load` command. Suppose, we have
the following entries in the /etc/hosts file:
```
# cat /etc/hosts
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
172.31.0.101 client101.xlat.net
2001:db8:200::101 client101.xlat.net
172.31.0.102 client102.xlat.net
2001:db8:200::102 client102.xlat.net
```
then `xlat load` command will add two entries into Jool EAM table as shown below.
```
# xlat.py load
# xlat.py list
+---------------------------------------------+--------------------+
|                                 IPv6 Prefix |        IPv4 Prefix |
+---------------------------------------------+--------------------+
|                       2001:db8:200::102/128 |    172.31.0.102/32 |
|                       2001:db8:200::101/128 |    172.31.0.101/32 |
|                           fd00:ab:cd::2/128 |   192.168.255.2/32 |
|                           fd00:ab:cd::1/128 | 192.168.100.104/32 |
+---------------------------------------------+--------------------+
```

## Generating /etc/hosts file from IPv6 only /etc/hosts file or from BIND9 IPv6 forward zone file
As we assume clients resides in an IPv6 only network, they do not have IPv4 addresses assigned to them but to communicate with the servers running in IPv4 networks, they need IPv4 addresses. So we assign a synthetic (private) IPv4 address to each of the client that corresponds to their IPv6 address and hostname. In order to simplify the IPv4 address assignment, XLAT script provides *gen* command which takes either an IPv6 BIND9 forward zone file (with a single domain) or an IPv6 only /etc/hosts file as input and generates an /etc/hosts file with both IPv4 and IPv6 addresses. Note that it allocates IPv4 addresses sequentially from the client IPv4 subnet specified in the XLAT config file. The limitations are it uses a single IPv4 subnet and assumes a single domain name in the zone file. It should be used once to generate the /etc/hosts file to ensure a unique IPv4 address is assigned to each IPv6 host.

To generate /etc/hosts file from a BIND9 IPv6 forward zone file, run the following command:

```
# xlat.py gen -v6zone /path/to/zonefile -domain ipv6test.net -hostsfile hosts
```

To generate /etc/hosts file from a IPv6 only hosts file, run the following command:

```
# xlat.py gen -v6host /path/to/hostsfile -hostsfile hosts
```

By the default it appends hosts entries to /etc/hosts file otherwise copy the generated hosts file to /etc/ directory and restart the `dnsmasq` service for name resolution. Note that you have to configure Jool EAMT entries using this hosts file as described in the previous section.

# DISCLAIMER
It uses the open source Jool software (unmodified version jool-4.1.14) downloaded from
the Network Information Centre Mexico (NIC Mexico) website https://www.jool.mx. 

# COPYRIGHT
Copyright (C) 2025 IBM Corporation.
