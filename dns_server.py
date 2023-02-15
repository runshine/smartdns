#!/bin/bash
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


def add_static_route_via_vtysh(dns_request, domain_config):
    ipv4_gw = domain_config['ipv4_gw']
    vtysh_static_route_cmd = 'ip route {} ' + ipv4_gw
    for ipv4_record in dns_request['ipv4']:
        subprocess.call(['vtysh','-c','config terminal','-c',vtysh_static_route_cmd.format(ipv4_addr_to_net(ipv4_record['addr']))],timeout=20)
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
            add_static_route_via_vtysh(dns_request,domain_config)
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


def start_zmq_server(args,record_collection,config_collection):
    zmq_socket = zmq.Context().socket(zmq.REP)
    zmq_socket.bind("ipc:///tmp/dns_server_zmq")
    config = read_config_collection(args,config_collection)
    _thread.start_new_thread(update_config_timer,(args,config,config_collection))
    with ThreadPoolExecutor(max_workers=1) as executor:
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='dns_server process.')
    parser.add_argument('--log',      metavar='l', type=str, required=False, help='log file')
    parser.add_argument('--zmq',      metavar='z', type=str, required=True, help='zmq server url, example: ipc:///tmp/dns_server, tcp://*.1234')
    parser.add_argument('--mongodb',  metavar='m', type=str, required=True, help='mongodb url, example: mongodb://localhost:27017/')
    parser.add_argument('--node_id',  metavar='n', type=str, required=True, help='node id, example: 10.10.8.1')
    parser.add_argument('--debug',    action='store_true', help='config if debug')
    args = parser.parse_args()
    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    if args.log is not None and len(args.log) != 0:
        logging.basicConfig(format='%(asctime)s %(message)s', filename=args.log, level=log_level)
    else:
        logging.basicConfig(format='%(asctime)s %(message)s', level=log_level)
    start_zmq_server(args,None,None)