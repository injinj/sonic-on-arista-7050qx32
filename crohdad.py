#!/usr/bin/python

import re
import time
import docker
import pprint
import os.path
import logging
import argparse
import ipaddress
import logging.handlers
from pyroute2 import IPRoute

# Prereqs
#apt-get update -y && apt-get install python-pip iproute2
#pip install docker pyroute2

version="0.91"

parser = argparse.ArgumentParser(description='Cumulus Routing on the Host Docker Advertisement Daemon (cRoHDAD) -- A Daemon to advertise Docker container IP addresses into Routing Fabrics running with Quagga/FRR.')
parser.add_argument('-d','--debug', action='store_true',
                   help='enables verbose logging output.')
parser.add_argument('-f','--no-flush-routes', action='store_false',
                   help='disables table flush of existing host-routes at startup.')
parser.add_argument('-l','--log-to-syslog-off', action='store_true',
                   help='disable logging to syslog.')
parser.add_argument('-t','--table_number', type=int,
                   help='route table number to add/remove host routes (see: /etc/iproute2/rt_tables). Default is 30')
parser.add_argument('-n','--no-add-on-start', action='store_true',
                   help='automatically detects existing containers and adds their host routes upon initial script start-up.')
parser.add_argument('-s','--subnets', action='append',
                   help='Allows the user to specify the acceptable container subnets which can be advertised via cRoHDAD when seen on containers. Defaults to advertising everything. example ./crohdad.py  --subnets 172.19.0.0/24 --subnets 172.17.0.0/24 ')
parser.add_argument('-v','--version', action='version', version="cRoHDAd version is v%s" % version,
                   help='Using this option displays the version of cRoHDAd and exits.')

args = parser.parse_args()


####################
# DEFAULT SETTINGS #
####################
# When enabled, this option will detect all containers
# running at startup and add the corresponding Host Routes
auto_add_on_startup=True
# Advertise Everything By Default
subnets_to_advertise=[]
#subnets_to_advertise=[u"172.19.0.0/24",u"172.20.0.0/24"]
log_to_syslog=True
log_location='/dev/log'
# Route Table Number To Add/Remove Host Routes
table_number=30

#Parse Arguments
debug=False
if args.debug: debug=True
if args.table_number: table_number=int(args.table_number)
if args.log_to_syslog_off: log_to_syslog=False
if args.no_add_on_start: auto_add_on_startup=False
if args.subnets:
    subnets_to_advertise=[]
    for subnet in args.subnets:
        subnets_to_advertise.append(unicode(subnet))

# PrettyPrint Setup
pp = pprint.PrettyPrinter(indent=4)

# Logging Setup
if log_to_syslog:
    log = logging.getLogger(__name__)
    log.setLevel(logging.DEBUG)
    if os.path.exists(log_location):
        try:
            handler = logging.handlers.SysLogHandler(address = log_location)
            formatter = logging.Formatter('container_advertisement: %(message)s')
            handler.setFormatter(formatter)
            log.addHandler(handler)
        except:
            print("WARNING: The syslog location '%s' could not be attached. Logging will occur via STDOUT only."%log_location)
            log_to_syslog=False
    else:
        print("WARNING: The syslog location '%s' does not exist. Logging will occur via STDOUT only."%log_location)
        log_to_syslog=False

# API Setup
client = docker.from_env()
low_level_client=docker.APIClient(base_url='unix://var/run/docker.sock')

# Pyroute2 Setup
ip = IPRoute()

# Data Structure to Store Container Info
container_IPs={} # Indexed by container_id
# container_ID:
#   network_ID:
#     bridge_ifindex:
#     ip_address:


def print_and_log(somestring):
    print somestring
    if log_to_syslog: log.info(somestring)

def remove_host_route(container_id):
    if container_id in container_IPs:
        for network_id in container_IPs[container_id]:
            ip_address=container_IPs[container_id][network_id][u'ip_address']
            ifindex=container_IPs[container_id][network_id][u'ifindex']
            print_and_log("    REMOVING Host Route: %s/32"%(ip_address))
            ip.route("del",
                     dst="%s/32"%(ip_address),
                     proto="boot",
                     table=table_number,
                     scope="link",
                     oif=ifindex)

def scrape_network_info(docker_container,container_id,network):
    if debug: print_and_log("DEBUG: Parsing Network: \"%s\" attached to container %s"%(network,container_id[:12]))
    if network == u'host': 
        if debug: print_and_log("DEBUG: Container %s is on a \"host\" network."%(container_id[:12]))
        return None,None,None

    # Scrape IP Address
    ip_address=None
    if docker_container[u'NetworkSettings'][u'Networks'][network][u'IPAMConfig'] != None:
        if u'IPv4Address' in docker_container[u'NetworkSettings'][u'Networks'][network][u'IPAMConfig']:
            ip_address=docker_container[u'NetworkSettings'][u'Networks'][network][u'IPAMConfig'][u'IPv4Address']
            if debug: print "DEBUG: Manually Assigned IP address Found %s (IPAM)."%(ip_address)
    elif docker_container[u'NetworkSettings'][u'Networks'][network][u'IPAddress'] != u'':
        ip_address=docker_container[u'NetworkSettings'][u'Networks'][network][u'IPAddress']
        if debug: print "DEBUG: Automatically Assigned IPv4 Address Found %s."%(ip_address)
    else:
        if debug: print_and_log("DEBUG: Container %s has no associated ip address on network %s."%(container_id[:12],network))
        return None,None,None

    # Scrape Network_ID
    network_id=docker_container[u'NetworkSettings'][u'Networks'][network][u'NetworkID']
    if network_id == u'':
        print_and_log("WARNING: Received bad network_id.")
        return None,None,None

    # Query Network_ID
    try:
        network_info=low_level_client.inspect_network(network_id)
    except:
        print_and_log("WARNING: Container %s: Unable to retrieve Docker Network Info."%(container_id[:12]))
        return None,None,None

    if debug:
        print("################[START Network id: %s]####################"%(network_id))
        pp.pprint(network_info)
        print("################[END Network id: %s]####################"%(network_id))


    if u'Driver' not in network_info: 
        return None,None,None

    if network_info[u'Driver']==u'bridge':
        # Scrape NAT
        if u'com.docker.network.bridge.enable_ip_masquerade' in network_info[u'Options']:
            nat_option=network_info[u'Options'][u'com.docker.network.bridge.enable_ip_masquerade']
            if nat_option == u'false': nat_enabled=False
            if nat_option == u'true':
                nat_enabled=True
                if debug: print_and_log("DEBUG: Container %s is attached to network %s (id:%s) which has NAT enabled. Please Disable NAT on this network."%(container_id[:12],network,network_id[:12]))
                return None,None,None

        # Scrape Bridge IFIndex
        if u'com.docker.network.bridge.name' in network_info[u'Options']:
            bridge_name=network_info[u'Options'][u'com.docker.network.bridge.name']
        else:
            bridge_name="br-%s"%(network_id[:12])
        ifindex = ip.link_lookup(ifname=bridge_name)[0]
    elif network_info[u'Driver']==u'macvlan':
        if u'parent' in network_info[u'Options']:
            parent_interface=network_info[u'Options'][u'parent']
        ifindex = ip.link_lookup(ifname=parent_interface)[0]
    else:
        print_and_log("INFO: Container %s: is attached to network %s (id:%s) which is not using the supported network drivers (Bridge or MACVlan)."%(container_id[:12],network,network_id[:12]))
        return None,None,None

    return ifindex,ip_address,network_id


def add_host_route(container_id):
    if debug: print_and_log("DEBUG: Querying Container ID: %s"%(container_id[:12]))
    time.sleep(0.2) # Waiting for Container to be Created
    try:
        docker_container=low_level_client.inspect_container(container_id)
    except:
        print_and_log("WARNING: Could not inspect container %s. Are you sure it still exists?"%(container_id[:12]))
        return
    if debug:
        print("################[START CONTAINER id: %s]####################"%(container_id[:12]))
        pp.pprint(docker_container)
        print("################[END CONTAINER id: %s]####################"%(container_id[:12]))

    for network in docker_container[u'NetworkSettings'][u'Networks']:

        if network == u'host': continue

        ifindex,ip_address,network_id=scrape_network_info(docker_container,container_id,network)

        if ip_address != None:
            ip_is_good=False
            if len(subnets_to_advertise) == 0: subnets_to_advertise.append(u'0.0.0.0/0')
            for subnet in subnets_to_advertise:
                if ipaddress.ip_address(ip_address) in ipaddress.ip_network(subnet):
                    ip_is_good=True
                    if debug: print_and_log("DEBUG: IP ADDRESS (%s) found in subnet (%s)"%(ip_address,subnet))
            if not ip_is_good:
                if debug: print_and_log("DEBUG: Container %s IP %s is not in the list of acceptable subnets for advertisement."%(container_id[:12],ip_address))
                continue
            # Store Container_ID, (Network_Id,IP_Address,Bridge_ifindex,Network_Id)
            if container_id not in container_IPs: container_IPs[container_id]={}
            if network_id not in container_IPs[container_id]: container_IPs[container_id][network_id]={}
            container_IPs[container_id][network_id][u'ifindex'] = ifindex
            container_IPs[container_id][network_id][u'ip_address'] = ip_address

            print_and_log("    ADDING Host Route: %s/32 (from container: %s)" %(ip_address,container_id[:12]))
            ip.route("add",
                     dst="%s/32"%(ip_address),
                     proto="boot",
                     table=table_number,
                     scope="link",
                     oif=ifindex)            

def add_route_table(table_number):
    try:
        with open("/etc/iproute2/rt_tables", "r+") as route_tables:
            for line in route_tables:
                if re.match("%s.*\w+"%(table_number),line):                  
                   break
            # not found, we are at the eof
            else:
                # append the containers table
                if debug: print("DEBUG: Creating Table %s in the Linux Routing Stack"%(table_number))
                route_tables.write("%s\tcontainers"%(table_number)) 
    except IOError as e:
        print_and_log("ERROR: Unable to open /etc/iproute2/rt_tables. Is IPRoute2 package installed? Are you not running this script as root?")
        exit(1)
    except:
        print_and_log("ERROR: Unexpected Error when trying to open /etc/iproute2/rt_tables.")
        exit(1)

    print_and_log("\n    *Adding All Host Routes to Table %s*\n      Run \"ip route show table %s\" to see routes."%(table_number,table_number))
    print_and_log("    Flushing any pre-existing routes from table %s."%(table_number))
    ip.flush_routes(table=table_number)


def main():
    print """
################################################
#                                              #
#     Cumulus Routing On the Host              #
#       Docker Advertisement Daemon            #
#             --cRoHDAd--                      #
#         originally written by Eric Pulvino   #
#                                              #
################################################
"""
    print_and_log(" STARTING UP.")

    add_route_table(table_number)

    if auto_add_on_startup:
        print_and_log("\n\n  Auto-Detecting existing containers and adding host routes...")
        try:
            container_list=client.containers.list()
        except:
            print_and_log("ERROR: Cannot Communicate with Docker-Engine API. Is Docker installed and started?")
            exit(1)
        for container in container_list:
            add_host_route(container.id)

    print_and_log("  Listening for Container Activity...")
    if debug: print "DEBUG: Printing all Docker events for debugging, it may get chatty..."
    try:
        events=client.events(decode=True)
    except:
        print_and_log("ERROR: Cannot Retreive Docker Events Stream. Is Docker installed and started?")
        exit(1)

    for event in events:
        if debug:
            pp.pprint(event)
        if u'status' in event:
            # Only look for specific event types
            # This approach will not catch runtime additions/removals of networks from existing containers.
            if event["status"] == "die" or event["status"] == "start":
                if u'Type' in event:
                    if event[u'Type'] != u'container': continue
                else: continue
                if event["status"] == "die":
                    print_and_log("STOPPED -- Container id: %s" % (event["id"]))
                    # Handle /32 Host Route Removal for Stopped Container (IF KNOWN)
                    #  This will become a threaded handling function... later.
                    remove_host_route(event["id"])
                elif event["status"] == "start":
                    print_and_log("STARTED -- Container id: %s" % (event["id"]))
                    # Handle /32 Host Route Addition for a Newly Started Container
                    #  This will become a threaded handling function... later.
                    add_host_route(event["id"])

if __name__ == "__main__":
    main()
