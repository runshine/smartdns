#! /usr/bin/env python3
import _thread
import argparse
import json
import logging
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
import socket
from logging.handlers import RotatingFileHandler

import pymongo
import operator
from readerwriterlock import rwlock


config_rw_lock = rwlock.RWLockFair()


def get_default_ipv4_gw():
    default_gw_outputs = ''.join(os.popen('ip route |grep default').readlines())
    default_gw = re.findall('\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)\s+',default_gw_outputs)
    if len(default_gw) != 0:
        default_gw = default_gw[0]
        logging.info("Get System Default IPV4 GW: {}".format(default_gw))
        return default_gw
    logging.error("Unable Get System Default IPV4 GW")
    return None

def get_default_ipv6_gw():
    default_gw_outputs = ''.join(os.popen("ip -6 route | grep default | egrep -o '([a-f0-9:]+:+)+[a-f0-9]+'").readlines()).strip()
    if len(default_gw_outputs) != 0:
        logging.info("Get System Default IPV6 GW: {}".format(default_gw_outputs))
        return default_gw_outputs
    logging.error("Unable Get System Default IPV6 GW")
    return None


system_default_gw = None
system_default_ipv6_gw = None

if "IP_RT_TABLE_ID" in os.environ.keys():
    ip_route_table_id = str(os.environ["IP_RT_TABLE_ID"])
else:
    ip_route_table_id = "254"


def get_domain_config(domain,config_array):
    global system_default_gw,system_default_ipv6_gw
    possible_domain_config = []
    read_marker = config_rw_lock.gen_rlock()
    read_marker.acquire()
    if config_array is None:
        return {'domain':domain,'ipv4_gw':system_default_gw,"ipv6_gw":system_default_ipv6_gw}
    else:
        for domain_config in config_array:
            if domain_config['domain'] == domain:
                read_marker.release()
                return domain_config
            if domain.endswith('.'+ domain_config['domain']):
                possible_domain_config.append((len(domain_config['domain'])+1,domain_config))
    read_marker.release()
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

def ipv6_addr_to_net(ipv6_addr):
    return ipv6_addr + "/64"


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
    global ip_route_table_id
    vtysh_static_route_cmd = 'ip route {} {} table {}'.format(static_net, ipv4_gw,ip_route_table_id)
    subprocess.call(['vtysh','-c','config terminal','-c',vtysh_static_route_cmd],timeout=20)


def vtysh_ipv6_add_one_static_route(static_net, ipv6_gw):
    global ip_route_table_id
    vtysh_static_route_cmd = 'ipv6 route {} {} table {}'.format(static_net, ipv6_gw,ip_route_table_id)
    subprocess.call(['vtysh','-c','config terminal','-c',vtysh_static_route_cmd],timeout=20)


def vtysh_ipv4_add_multi_static_route(static_net_list, ipv4_gw):
    global ip_route_table_id
    process=subprocess.Popen(['vtysh'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    send_data = "config terminal\n"
    for static_net in static_net_list:
        send_data = send_data + "ip route {} {} table {}\n".format(static_net, ipv4_gw,ip_route_table_id)
    send_data = send_data + "quit\n" + "quit\n"
    stdout, stderr = process.communicate(send_data.encode('utf-8'),timeout=30)


def vtysh_ipv4_remove_multi_static_rotue(static_net_list):
    global ip_route_table_id
    process=subprocess.Popen(['vtysh'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    send_data = "config ter\n"
    for static_net in static_net_list:
        send_data = send_data + "no ip route {} {} table {}\n".format(static_net[0], static_net[1],ip_route_table_id)
    send_data = send_data + "quit\n" + "quit\n"
    stdout, stderr = process.communicate(send_data.encode('utf-8'),timeout=30)


def add_static_route(dns_request, domain_config):
    try:
        if 'ipv4_gw' in domain_config.keys():
            ipv4_gw = domain_config['ipv4_gw']
            if ipv4_gw is not None and len(ipv4_gw) != 0:
                if 'ipv4' in dns_request.keys():
                    for ipv4_record in dns_request['ipv4']:
                        vtysh_ipv4_add_one_static_route(ipv4_addr_to_net(ipv4_record['addr']),ipv4_gw)
                        logging.info("[vtysh]: ip add {} to gw:{}, request: {}, match: {}, alias domain: {}".format(ipv4_addr_to_net(ipv4_record['addr']),ipv4_gw,dns_request['request-domain'],domain_config['domain'],ipv4_record['domain']))
                if 'ipv4_net' in dns_request.keys():
                    for ipv4_net_record in dns_request['ipv4_net']:
                        vtysh_ipv4_add_one_static_route(ipv4_net_record['addr'],ipv4_gw)
                        logging.info("[vtysh]: ipv4 net add {} to gw:{}, request: {}, match: {}, alias domain: {}".format(ipv4_net_record['addr'],ipv4_gw,dns_request['request-domain'],domain_config['domain'],ipv4_net_record['domain']))
    except Exception as e:
        logging.error("Error happened in add ipv4 static route, error: " + str(e))

    try:
        if 'ipv6_gw' in domain_config.keys():
            ipv6_gw = domain_config['ipv6_gw']
            if ipv6_gw is not None and len(ipv6_gw) != 0:
                if 'ipv6' in dns_request.keys():
                    for ipv6_record in dns_request['ipv6']:
                        vtysh_ipv6_add_one_static_route(ipv6_addr_to_net(ipv6_record['addr']),ipv6_gw)
                        logging.info("[vtysh]: ipv6 add {} to gw:{}, request: {}, match: {}, alias domain: {}".format(ipv6_addr_to_net(ipv6_record['addr']),ipv6_gw,dns_request['request-domain'],domain_config['domain'],ipv6_record['domain']))
                    if 'ipv6_net' in dns_request.keys():
                        for ipv6_net_record in dns_request['ipv6_net']:
                            vtysh_ipv6_add_one_static_route(ipv6_net_record['addr'],ipv6_gw)
                            logging.info("[vtysh]: ipv6 net add {} to gw:{}, request: {}, match: {}, alias domain: {}".format(ipv6_net_record['addr'],ipv6_gw,dns_request['request-domain'],domain_config['domain'],ipv6_net_record['domain']))
    except Exception as e:
        logging.error("Error happened in add ipv6 static route, error: " + str(e))


def add_dns_record_to_db(record_collection,dns_request, domain_config):
    pass


def process_dns_request(record_collection,config,dns_request_json):
    global system_default_gw,system_default_ipv6_gw
    try:
        dns_request = json.loads(dns_request_json)
        logging.debug("recv a dns request: {}".format(dns_request))
        if 'request-domain' in dns_request.keys():
            #means this is a dns request
            domain_config = get_domain_config(dns_request['request-domain'],config)
        elif 'request-ip' in dns_request.keys():
            #means this is a ip request
            domain_config = {'domain':"*",'ipv4_gw':system_default_gw,"ipv6_gw":system_default_ipv6_gw}
            dns_request['request-domain'] = "*"
        else:
            logging.error("unsupport request type: {}".format(dns_request))
            domain_config = None
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
                        config_array.append({'domain':host,'ipv4_gw':gw,'ipv6_gw':system_default_ipv6_gw})
    return config_array


def vtysh_clear_all_static_route(dns_ip):
    logging.info("Start clear all static route, except dns: {}/32".format(dns_ip))
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
        write_marker = config_rw_lock.gen_wlock()
        write_marker.acquire()
        logging.info("config update, differ: {}, befor: {}, after: {}".format(len(differ),len(config_hashset),len(new_config_hashset)))
        config.clear()
        config.extend(new_config)
        config_hashset = new_config_hashset
        write_marker.release()


def config_dns_route(dns_ip):
    vtysh_ipv4_add_one_static_route(dns_ip +"/32", get_default_ipv4_gw())


def start_socket_server(args,record_collection,config_collection):
    socket_proto_url = args.socket
    socket_proto = re.findall("\s*(.+)://\d+\.\d+\.\d+\.\d+",socket_proto_url)
    if len(socket_proto) != 1:
        logging.error("failed to parse socket proto url: {}, proto error".format(socket_proto_url))
        exit(-1)
    socket_proto = socket_proto[0]
    socket_addr = re.findall("\s*.+://(\d+\.\d+\.\d+\.\d+)",socket_proto_url)
    if len(socket_addr) != 1:
        logging.error("failed to parse socket proto url: {}, addr error".format(socket_proto_url))
        exit(-1)
    socket_addr = socket_addr[0]
    socket_port = re.findall("\s*.+://\d+\.\d+\.\d+\.\d+:(\d+)",socket_proto_url)
    if len(socket_port) != 1:
        socket_port = 34321
    else:
        socket_port = int(socket_port[0])
    logging.info("Start socket server: proto: {}, addr: {}, port: {}".format(socket_proto,socket_addr,socket_port))
    recv_message = None
    if socket_proto == "udp":
        server_socket_fd = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        server_socket_fd.bind((socket_addr, socket_port))

        def udp_recv_message():
            bytesAddressPair = server_socket_fd.recvfrom(65535)
            message = bytesAddressPair[0]
            try:
                return message.decode('utf-8')
            except Exception as e:
                return None
        recv_message = udp_recv_message
    else:
        logging.error("current not support socket proto: {}".format(socket_proto_url))
        exit(-1)

    if args.default is not True:
        logging.info("Use as config dns server, config dis is: /etc/dnsmasq.d/")
        config = read_config_collection(args,config_collection)
        _thread.start_new_thread(update_config_timer,(args,config,config_collection))
    else:
        logging.info("Use as all default dns server")
        config = None
    # with ThreadPoolExecutor(max_workers=10) as executor:
    #     while True:
    #         messages = recv_message()
    #         executor.submit(process_dns_request,record_collection,config,messages)
    while True:
        messages = recv_message()
        process_dns_request(record_collection,config,messages)


def connect_to_mongodb(url):
    myclient = pymongo.MongoClient(url)
    dblist = myclient.list_database_names()
    dns = myclient['dns']
    dns_record_collection = dns['record']
    config_collection = dns['config']
    return dns_record_collection,config_collection


def process_ip_file(ip_file):
    logging.info("process ip file: {}".format(ip_file))
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
            logging.error("failed to open extra file, not exist: {}, ignore it".format(args.extra))
            return
        if os.path.isfile(args.extra):
            process_ip_file(args.extra)
        elif os.path.isdir(args.extra):
            for file in os.listdir(args.extra):
                ip_file = os.path.join(args.extra,file)
                if os.path.isfile(ip_file):
                    process_ip_file(ip_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='dns_server process.')
    parser.add_argument('--log',      metavar='l', type=str, required=False, help='log file')
    parser.add_argument('--mongodb',  metavar='m', type=str, required=True,  help='mongodb url, example: mongodb://localhost:27017/')
    parser.add_argument('--node_id',  metavar='n', type=str, required=True,  help='node id, example: 10.10.8.1, current not use')
    parser.add_argument('--dns',      metavar='d', type=str, required=True,  help='dns IP, example: 8.8.8.8')
    parser.add_argument('--socket',   metavar='u', type=str, required=False,  help='server proto, current support udp, example: udp://127.0.0.1:1234')
    parser.add_argument('--extra',    metavar='e', type=str, required=False, help='extra_ip_net list file')
    parser.add_argument('--debug',    action='store_true', help='config if debug')
    parser.add_argument('--default',  action='store_true', help='use as all default with any dns request, ignore /etc/dnsmasq.d config')
    parser.add_argument('--clear',    action='store_true', help='clear all static route')
    args = parser.parse_args()
    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logFormatter = "%(asctime)s [%(threadName)s] [%(levelname)-5.5s]  %(message)s"
    if args.log is not None and len(args.log) != 0:
        fileHandler = RotatingFileHandler(args.log, mode='a', maxBytes=5 * 1024 * 1024, backupCount=1, encoding='utf-8', delay=False)
        fileHandler.setFormatter(logging.Formatter(logFormatter))
        logging.basicConfig(format=logFormatter, level=log_level,handlers=[fileHandler])
    else:
        logging.basicConfig(format=logFormatter, level=log_level,handlers=[logging.StreamHandler(sys.stdout)])
    logging.info("start smartdns-server python server ,log_level: {}".format(log_level))
    system_default_gw = get_default_ipv4_gw()
    system_default_ipv6_gw = get_default_ipv6_gw()
    if args.clear:
        if 'dns' in args.keys():
            vtysh_clear_all_static_route(args.dns)
        process_extra_ip(args)
        exit(0)
    process_extra_ip(args)
    if args.socket is not None:
        start_socket_server(args, None, None)
    else:
        logging.error("not start any server, you must special ether zmq or socket server proto")
        exit(-1)