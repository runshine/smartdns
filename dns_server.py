#! /usr/bin/env python3
import _thread
import argparse
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import zmq
import pymongo
import operator


config_lock = threading.Lock()


def get_domain_config(domain,config_array):
    possible_domain_config = []
    config_lock.acquire()
    for domain_config in config_array:
        if domain_config['domain'] == domain:
            config_lock.release()
            return domain_config
        if domain.endswith('.'+ domain_config['domain']):
            possible_domain_config.append((len(domain_config['domain'])+1,domain_config))
    config_lock.release()
    max_len = 0
    for domain_len,domain_config in possible_domain_config:
        if max_len < domain_len:
            max_len = domain_len
    for domain_len,domain_config in possible_domain_config:
        if max_len == domain_len:
            return domain_config
    return None


def ipv4_addr_to_net(ipv4_addr):
    return ipv4_addr[:ipv4_addr.rfind('.')] + ".0/24"


def vtysh_list_static_route():
    vtysh_route_output = ''.join(os.popen('echo "show ip route static" | vtysh | grep -v Codes|grep S|grep -v OSPF|grep -v SHARP|grep -v inactive').readlines()).strip()
    result = []
    for line in vtysh_route_output.split('\n'):
        if line.find('via') != -1:
            test = re.findall('\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+[\[\]\d/]+\s+via\s+(\d+\.\d+\.\d+\.\d+)',line)
            if len(test) != 0:
                result.append(test[0])
    return result


def vtysh_ipv4_add_one_static_route(static_net, ipv4_gw):
    vtysh_static_route_cmd = 'ip route {} {}'.format(static_net, ipv4_gw)
    subprocess.call(['vtysh','-c','config terminal','-c',vtysh_static_route_cmd],timeout=20)


def vtysh_ipv4_add_multi_static_route(static_net_list, ipv4_gw):
    process=subprocess.Popen(['vtysh'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    send_data = "config terminal\n"
    for static_net in static_net_list:
        send_data = send_data + "ip route {} {}\n".format(static_net, ipv4_gw)
    send_data = send_data + "quit\n" + "quit\n"
    stdout, stderr = process.communicate(send_data.encode('utf-8'),timeout=30)


def vtysh_ipv4_remove_multi_static_rotue(static_net_list):
    process=subprocess.Popen(['vtysh'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    send_data = "config ter\n"
    for static_net in static_net_list:
        send_data = send_data + "no ip route {} {}\n".format(static_net[0], static_net[1])
    send_data = send_data + "quit\n" + "quit\n"
    stdout, stderr = process.communicate(send_data.encode('utf-8'),timeout=30)



def add_static_route(dns_request, domain_config):
    ipv4_gw = domain_config['ipv4_gw']
    for ipv4_record in dns_request['ipv4']:
        vtysh_ipv4_add_one_static_route(ipv4_addr_to_net(ipv4_record['addr']),ipv4_gw)
        logging.info("[vtysh]: add {} to gw:{}, request: {}, match: {}, alias domain: {}".format(ipv4_addr_to_net(ipv4_record['addr']),ipv4_gw,dns_request['request-domain'],domain_config['domain'],ipv4_record['domain']))
    for ipv6_record in dns_request['ipv6']:
        pass


def add_dns_record_to_db(record_collection,dns_request, domain_config):
    pass


def process_dns_request(record_collection,config,dns_request_json):
    try:
        dns_request = json.loads(dns_request_json)
        domain_config = get_domain_config(dns_request['request-domain'],config)
        if domain_config is None:
            return
        else:
            add_static_route(dns_request,domain_config)
            add_dns_record_to_db(record_collection,dns_request,domain_config)
    except Exception as e:
        logging.error("Error happened: {} --> {}".format(e.__class__.__name__,str(e)))


def read_config_collection(args,config_collection):
    #return config_collection.find({'node':args.node_id})
    return read_config_from_dnsmasq('/etc/dnsmasq.d/')


def get_default_ipv4_gw():
    default_gw_outputs = ''.join(os.popen('ip route |grep default').readlines())
    default_gw = re.findall('\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)\s+',default_gw_outputs)
    if len(default_gw) != 0:
        default_gw = default_gw[0]
        return default_gw
    return None


def read_config_from_dnsmasq(dnsmasq_config_dir):
    config_array = []
    gw = get_default_ipv4_gw()
    for root,folders,files in os.walk(dnsmasq_config_dir):
        for file in files:
            conf_file = os.path.join(root,file)
            if file.endswith('.conf'):
                with open(conf_file) as pfile:
                    for line in pfile.readlines():
                        line = line.strip()
                        if re.match('\\s*#',line) is not None:
                            continue
                        host = re.findall('\s*server\s*=\s*/([^/]+)/.*',line)
                        if len(host) == 0:
                            continue
                        host = host[0]
                        config_array.append({'domain':host,'ipv4_gw':gw})
    return config_array


def vtysh_clear_all_static_route(dns_ip):
    dns_net = (dns_ip + "/32",get_default_ipv4_gw())
    static_net_list = vtysh_list_static_route()
    for static_net in static_net_list:
        if operator.eq(dns_net,static_net) :
            static_net_list.remove(static_net)
            break
    vtysh_ipv4_remove_multi_static_rotue(static_net_list)


def convert_config_hashset(config):
    return [str(x) for x in config]


def update_config_timer(args,config,config_collection):
    config_hashset = convert_config_hashset(config)
    while True:
        time.sleep(5)
        new_config = read_config_collection(args,config_collection)
        new_config_hashset = convert_config_hashset(new_config)
        differ = set(config_hashset) ^ set(new_config_hashset)
        if len(differ) == 0:
            continue
        config_lock.acquire()
        logging.info("config update, differ: {}".format(len(differ)))
        config.clear()
        config = config + new_config
        config_hashset = new_config_hashset
        config_lock.release()


def config_dns_route(dns_ip):
    vtysh_ipv4_add_one_static_route(dns_ip +"/32", get_default_ipv4_gw())


def start_zmq_server(args,record_collection,config_collection):
    zmq_socket = zmq.Context().socket(zmq.REP)
    zmq_socket.bind("ipc:///tmp/dns_server_zmq")
    config = read_config_collection(args,config_collection)
    _thread.start_new_thread(update_config_timer,(args,config,config_collection))
    with ThreadPoolExecutor(max_workers=10) as executor:
        while True:
            messages = zmq_socket.recv_string()
            executor.submit(process_dns_request,record_collection,config,messages)
            zmq_socket.send_string("ok")


def connect_to_mongodb(url):
    myclient = pymongo.MongoClient(url)
    dblist = myclient.list_database_names()
    dns = myclient['dns']
    dns_record_collection = dns['record']
    config_collection = dns['config']
    return dns_record_collection,config_collection


def process_ip_file(ip_file):
    ipv4_gw = get_default_ipv4_gw()
    with open(ip_file) as f:
        for line in f.readlines():
            line = line.strip()
            if line.startswith("#") or len(line) == 0:
                continue
            if re.match("\d+\.\d+\.\d+\.\d+/\d+",line) is not None:
                vtysh_ipv4_add_one_static_route(line,ipv4_gw)
                logging.info("add static ip net from ip file: {} -- {},{}".format(ip_file,line,ipv4_gw))


def process_extra_ip(args):
    if args.extra is not None and len(args.extra) != 0:
        if not os.path.exists(args.extra):
            logging.error("failed to open extra file, not exist: {}".format(args.extra))
            exit(-1)
        process_ip_file(args.extra)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='dns_server process.')
    parser.add_argument('--log',      metavar='l', type=str, required=False, help='log file')
    parser.add_argument('--zmq',      metavar='z', type=str, required=True,  help='zmq server url, example: ipc:///tmp/dns_server, tcp://*.1234')
    parser.add_argument('--mongodb',  metavar='m', type=str, required=True,  help='mongodb url, example: mongodb://localhost:27017/')
    parser.add_argument('--node_id',  metavar='n', type=str, required=True,  help='node id, example: 10.10.8.1')
    parser.add_argument('--dns',      metavar='d', type=str, required=True,  help='dns IP, example: 8.8.8.8')
    parser.add_argument('--extra',    metavar='e', type=str, required=False, help='extra_ip_net list file')
    parser.add_argument('--debug',    action='store_true', help='config if debug')
    parser.add_argument('--clear',    action='store_true', help='clear all static route')
    args = parser.parse_args()
    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    if args.log is not None and len(args.log) != 0:
        logging.basicConfig(format='%(asctime)s %(message)s', filename=args.log, level=log_level)
    else:
        logging.basicConfig(format='%(asctime)s %(message)s', level=log_level)
    if args.clear:
        vtysh_clear_all_static_route(args.dns)
        process_extra_ip(args)
        exit(0)
    process_extra_ip(args)
    start_zmq_server(args,None,None)