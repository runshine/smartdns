#! /usr/bin/env python3
import argparse
import hashlib
import json
import logging
import os
import re
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, Iterable, List, Optional, Tuple

from readerwriterlock import rwlock

try:
    import uvicorn
    from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, ConfigDict, Field, field_validator
except ImportError:  # pragma: no cover - handled at runtime
    uvicorn = None
    FastAPI = None

    def Depends(value=None):
        return value

    def Header(default=None, *args, **kwargs):
        del args, kwargs
        return default

    def Query(default=None, *args, **kwargs):
        del args, kwargs
        return default

    HTTPException = Exception
    Request = None

    class BaseModel:
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)

        def model_dump(self):
            return self.__dict__.copy()

    class ConfigDict(dict):
        pass

    def Field(default=None, *args, **kwargs):
        del args, kwargs
        return default

    def field_validator(*args, **kwargs):
        del args, kwargs

        def decorator(func):
            return func

        return decorator

    class JSONResponse:
        def __init__(self, status_code=200, content=None):
            self.status_code = status_code
            self.content = content


ASCENDING = 1
DESCENDING = -1

config_rw_lock = rwlock.RWLockFair()
system_default_gw = None
system_default_ipv6_gw = None
vtysh_console = None
state = None


class DuplicateKeyError(Exception):
    pass


class ReturnDocument:
    BEFORE = 'before'
    AFTER = 'after'


class SimpleResult:
    def __init__(self, inserted_id=None, deleted_count=0):
        self.inserted_id = inserted_id
        self.deleted_count = deleted_count


class SQLiteAdmin:
    def __init__(self, db):
        self.db = db

    def command(self, command_name):
        if command_name != 'ping':
            raise ValueError(f'unsupported command: {command_name}')
        self.db.execute('SELECT 1')
        return {'ok': 1}


class SQLiteClient:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.admin = SQLiteAdmin(conn)

    def close(self):
        self.conn.close()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if value is None or value == '':
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    try:
        if value.endswith('Z'):
            value = value[:-1] + '+00:00'
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError as exc:
        raise ValueError(f'invalid datetime: {value}') from exc


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower().rstrip('.')
    if not domain:
        raise ValueError('domain cannot be empty')
    return domain


def validate_ipv4(value: Optional[str]) -> Optional[str]:
    if value is None or value == '':
        return None
    parts = value.split('.')
    if len(parts) != 4:
        raise ValueError(f'invalid IPv4 gateway: {value}')
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            raise ValueError(f'invalid IPv4 gateway: {value}')
    return value


def validate_ipv6(value: Optional[str]) -> Optional[str]:
    if value is None or value == '':
        return None
    try:
        socket.inet_pton(socket.AF_INET6, value)
    except OSError as exc:
        raise ValueError(f'invalid IPv6 gateway: {value}') from exc
    return value


def ensure_fastapi_installed():
    if FastAPI is None or uvicorn is None:
        raise RuntimeError('fastapi/uvicorn is required for REST API support')


def serialize_storage_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return {'__datetime__': isoformat(value)}
    if isinstance(value, list):
        return [serialize_storage_value(item) for item in value]
    if isinstance(value, dict):
        return {key: serialize_storage_value(item) for key, item in value.items()}
    return value


def deserialize_storage_value(value: Any) -> Any:
    if isinstance(value, list):
        return [deserialize_storage_value(item) for item in value]
    if isinstance(value, dict):
        if set(value.keys()) == {'__datetime__'}:
            return parse_datetime(value['__datetime__'])
        return {key: deserialize_storage_value(item) for key, item in value.items()}
    return value


def get_default_ipv4_gw():
    default_gw_outputs = ''.join(os.popen(r'ip route |grep default').readlines())
    default_gw = re.findall(r'\s+(\d+\.\d+\.\d+\.\d+)\s+', default_gw_outputs)
    if len(default_gw) != 0:
        default_gw = default_gw[0]
        logging.info('Get System Default IPV4 GW: %s', default_gw)
        return default_gw
    logging.error('Unable Get System Default IPV4 GW')
    return None


def get_default_ipv6_gw():
    default_gw_outputs = ''.join(
        os.popen(r"ip -6 route | grep default | egrep -o '([a-f0-9:]+:+)+[a-f0-9]+' ").readlines()
    ).strip()
    if len(default_gw_outputs) != 0:
        logging.info('Get System Default IPV6 GW: %s', default_gw_outputs)
        return default_gw_outputs
    logging.error('Unable Get System Default IPV6 GW')
    return None


def vtysh_console_readline(console, timeout=0, log=True):
    del timeout
    line = ''
    while True:
        text = console.stdout.read(1).decode('utf-8')
        line = line + text
        if text == '#' or text == '\n':
            break
    if log:
        logging.info(line.strip())
    return line


def vtysh_console_read_until(console, char):
    line = ''
    while True:
        text = console.stdout.read(1).decode('utf-8')
        line = line + text
        if text == char:
            break
    return line


def start_vtysh_console():
    while True:
        try:
            logging.info('try to connect to vtysh')
            console = subprocess.Popen(
                ['vtysh'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False
            )
            line = vtysh_console_readline(console)
            while line.find('#') == -1:
                line = vtysh_console_readline(console)
            logging.info("write 'config terminal' to vtysh console")
            console.stdin.write('config terminal\n'.encode('utf-8'))
            console.stdin.flush()
            line = vtysh_console_readline(console)
            while line.find('config') == -1:
                line = vtysh_console_readline(console)
            logging.info('success to connect to vtysh')
            return console
        except Exception as exc:
            logging.error('start_vtysh_console error happened, try it again: %s', exc)
            time.sleep(1)


def write_vtysh_line(line):
    global vtysh_console
    while True:
        try:
            vtysh_console.stdin.write(line.encode('utf-8'))
            vtysh_console.stdin.flush()
            vtysh_console_read_until(vtysh_console, '#')
            return
        except Exception as exc:
            logging.error('write to vtysh console error, try it again: error:%s', exc)
        vtysh_console = start_vtysh_console()
        time.sleep(1)


if 'IP_RT_TABLE_ID' in os.environ.keys():
    ip_route_table_id = str(os.environ['IP_RT_TABLE_ID'])
else:
    ip_route_table_id = '254'


class AppState:
    def __init__(self, args):
        self.args = args
        self.db_client = None
        self.record_collection = None
        self.config_collection = None
        self.stats_collection = None
        self.meta_collection = None
        self.config_cache: List[Dict[str, Any]] = []
        self.stop_event = threading.Event()
        self.last_request_at: Optional[datetime] = None
        self.last_error: Optional[str] = None
        self.socket_thread: Optional[threading.Thread] = None
        self.api_thread: Optional[threading.Thread] = None
        self.db_lock = threading.Lock()
        self.config_refresh_interval = args.config_refresh_interval
        self.api_token_hash = hash_token(args.api_token) if args.api_token else None
        self.db_available = False
        self.db_disabled_reason: Optional[str] = None

    def touch_request(self):
        self.last_request_at = utcnow()

    def set_error(self, message: str):
        self.last_error = message

    def set_db_state(self, available: bool, reason: Optional[str] = None):
        self.db_available = available
        self.db_disabled_reason = reason


def get_domain_config(domain, config_array):
    global system_default_gw, system_default_ipv6_gw
    possible_domain_config = []
    read_marker = config_rw_lock.gen_rlock()
    read_marker.acquire()
    try:
        if config_array is None:
            return {'domain': domain, 'ipv4_gw': system_default_gw, 'ipv6_gw': system_default_ipv6_gw}
        for domain_config in config_array:
            if domain_config['domain'] == domain:
                return domain_config
            if domain.endswith('.' + domain_config['domain']):
                possible_domain_config.append((len(domain_config['domain']) + 1, domain_config))
    finally:
        read_marker.release()
    max_len = 0
    for domain_len, domain_config in possible_domain_config:
        if max_len < domain_len:
            max_len = domain_len
    for domain_len, domain_config in possible_domain_config:
        if max_len == domain_len:
            return domain_config
    return None


def ipv4_addr_to_net(ipv4_addr):
    return ipv4_addr[:ipv4_addr.rfind('.')] + '.0/24'


def ipv6_addr_to_net(ipv6_addr):
    return ipv6_addr + '/64'


def vtysh_list_static_route():
    global ip_route_table_id
    vtysh_route_output = ''.join(
        os.popen(
            f'echo "show ip route table {ip_route_table_id}" | vtysh | grep -v Codes|grep S|grep -v OSPF|grep -v SHARP|grep -v inactive'
        ).readlines()
    ).strip()
    result = []
    for line in vtysh_route_output.split('\n'):
        if line.find('via') != -1:
            test = re.findall(r'\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+[\[\]\d/]+\s+via\s+(\d+\.\d+\.\d+\.\d+)', line)
            if len(test) != 0:
                result.append(test[0])
    return result


def vtysh_ipv4_add_one_static_route(static_net, ipv4_gw):
    global ip_route_table_id
    vtysh_static_route_cmd = f'ip route {static_net} {ipv4_gw} table {ip_route_table_id}\n'
    write_vtysh_line(vtysh_static_route_cmd)


def vtysh_ipv6_add_one_static_route(static_net, ipv6_gw):
    vtysh_static_route_cmd = f'ipv6 route {static_net} {ipv6_gw}\n'
    write_vtysh_line(vtysh_static_route_cmd)


def vtysh_ipv4_add_multi_static_route(static_net_list, ipv4_gw):
    global ip_route_table_id
    process = subprocess.Popen(['vtysh'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    send_data = 'config terminal\n'
    for static_net in static_net_list:
        send_data = send_data + f'ip route {static_net} {ipv4_gw} table {ip_route_table_id}\n'
    send_data = send_data + 'quit\nquit\n'
    process.communicate(send_data.encode('utf-8'), timeout=30)


def vtysh_ipv4_remove_multi_static_rotue(static_net_list):
    global ip_route_table_id
    process = subprocess.Popen(['vtysh'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    send_data = 'config ter\n'
    for static_net in static_net_list:
        send_data = send_data + f'no ip route {static_net[0]} {static_net[1]} table {ip_route_table_id}\n'
    send_data = send_data + 'quit\nquit\n'
    process.communicate(send_data.encode('utf-8'), timeout=30)


def sanitize_answer_records(records: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    sanitized = []
    for record in records or []:
        if not isinstance(record, dict):
            continue
        item = {}
        for key in ('addr', 'domain', 'ttl'):
            if key in record:
                item[key] = record[key]
        if 'addr' in item:
            sanitized.append(item)
    return sanitized


def add_static_route(dns_request, domain_config):
    route_actions = []
    try:
        if 'ipv4_gw' in domain_config.keys():
            ipv4_gw = domain_config['ipv4_gw']
            if ipv4_gw:
                if 'ipv4' in dns_request.keys():
                    for ipv4_record in dns_request['ipv4']:
                        target = ipv4_addr_to_net(ipv4_record['addr'])
                        try:
                            vtysh_ipv4_add_one_static_route(target, ipv4_gw)
                            route_actions.append({'family': 'ipv4', 'target': target, 'gateway': ipv4_gw, 'status': 'applied'})
                            logging.info(
                                '[vtysh]: ip add %s to gw:%s, request: %s, match: %s, alias domain: %s',
                                target, ipv4_gw, dns_request['request-domain'], domain_config['domain'], ipv4_record.get('domain')
                            )
                        except Exception as exc:
                            route_actions.append({'family': 'ipv4', 'target': target, 'gateway': ipv4_gw, 'status': 'error', 'error': str(exc)})
                if 'ipv4_net' in dns_request.keys():
                    for ipv4_net_record in dns_request['ipv4_net']:
                        target = ipv4_net_record['addr']
                        try:
                            vtysh_ipv4_add_one_static_route(target, ipv4_gw)
                            route_actions.append({'family': 'ipv4', 'target': target, 'gateway': ipv4_gw, 'status': 'applied'})
                            logging.info(
                                '[vtysh]: ipv4 net add %s to gw:%s, request: %s, match: %s, alias domain: %s',
                                target, ipv4_gw, dns_request['request-domain'], domain_config['domain'], ipv4_net_record.get('domain')
                            )
                        except Exception as exc:
                            route_actions.append({'family': 'ipv4', 'target': target, 'gateway': ipv4_gw, 'status': 'error', 'error': str(exc)})
    except Exception as exc:
        logging.error('Error happened in add ipv4 static route, error: %s', exc)
        route_actions.append({'family': 'ipv4', 'status': 'error', 'error': str(exc)})

    try:
        if 'ipv6_gw' in domain_config.keys():
            ipv6_gw = domain_config['ipv6_gw']
            if ipv6_gw:
                if 'ipv6' in dns_request.keys():
                    for ipv6_record in dns_request['ipv6']:
                        target = ipv6_addr_to_net(ipv6_record['addr'])
                        try:
                            vtysh_ipv6_add_one_static_route(target, ipv6_gw)
                            route_actions.append({'family': 'ipv6', 'target': target, 'gateway': ipv6_gw, 'status': 'applied'})
                            logging.info(
                                '[vtysh]: ipv6 add %s to gw:%s, request: %s, match: %s, alias domain: %s',
                                target, ipv6_gw, dns_request['request-domain'], domain_config['domain'], ipv6_record.get('domain')
                            )
                        except Exception as exc:
                            route_actions.append({'family': 'ipv6', 'target': target, 'gateway': ipv6_gw, 'status': 'error', 'error': str(exc)})
                if 'ipv6_net' in dns_request.keys():
                    for ipv6_net_record in dns_request['ipv6_net']:
                        target = ipv6_net_record['addr']
                        try:
                            vtysh_ipv6_add_one_static_route(target, ipv6_gw)
                            route_actions.append({'family': 'ipv6', 'target': target, 'gateway': ipv6_gw, 'status': 'applied'})
                            logging.info(
                                '[vtysh]: ipv6 net add %s to gw:%s, request: %s, match: %s, alias domain: %s',
                                target, ipv6_gw, dns_request['request-domain'], domain_config['domain'], ipv6_net_record.get('domain')
                            )
                        except Exception as exc:
                            route_actions.append({'family': 'ipv6', 'target': target, 'gateway': ipv6_gw, 'status': 'error', 'error': str(exc)})
    except Exception as exc:
        logging.error('Error happened in add ipv6 static route, error: %s', exc)
        route_actions.append({'family': 'ipv6', 'status': 'error', 'error': str(exc)})
    return route_actions


def normalize_dns_request(raw_request: Dict[str, Any], domain_config: Optional[Dict[str, Any]], route_actions: List[Dict[str, Any]],
                          parsed: bool = True, error: Optional[str] = None) -> Dict[str, Any]:
    matched_domain = domain_config.get('domain') if domain_config else None
    request_domain = raw_request.get('request-domain')
    if request_domain:
        request_domain = normalize_domain(request_domain)
    document = {
        'request_domain': request_domain,
        'request_ip': raw_request.get('request-ip'),
        'request_type': 'domain' if request_domain not in (None, '*') else 'ip',
        'matched_domain': matched_domain,
        'node_id': state.args.node_id,
        'ipv4': sanitize_answer_records(raw_request.get('ipv4')),
        'ipv4_net': sanitize_answer_records(raw_request.get('ipv4_net')),
        'ipv6': sanitize_answer_records(raw_request.get('ipv6')),
        'ipv6_net': sanitize_answer_records(raw_request.get('ipv6_net')),
        'route_actions': route_actions,
        'raw_request': raw_request,
        'created_at': utcnow(),
        'status': {
            'parsed': parsed,
            'matched': domain_config is not None,
            'route_applied': any(item.get('status') == 'applied' for item in route_actions),
            'error': error,
        },
        'gateways': {
            'ipv4_gw': domain_config.get('ipv4_gw') if domain_config else None,
            'ipv6_gw': domain_config.get('ipv6_gw') if domain_config else None,
        },
    }
    return document


def get_nested(document: Dict[str, Any], dotted_key: str):
    value = document
    for part in dotted_key.split('.'):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def match_value(actual, condition):
    if isinstance(condition, dict):
        for op, expected in condition.items():
            if op == '$gte' and not (actual is not None and actual >= expected):
                return False
            if op == '$lte' and not (actual is not None and actual <= expected):
                return False
            if op == '$lt' and not (actual is not None and actual < expected):
                return False
            if op == '$ne' and actual == expected:
                return False
        return True
    return actual == condition


def filter_documents(documents: Iterable[Dict[str, Any]], query: Dict[str, Any]) -> List[Dict[str, Any]]:
    results = []
    for document in documents:
        matched = True
        for key, condition in query.items():
            actual = get_nested(document, key)
            if not match_value(actual, condition):
                matched = False
                break
        if matched:
            results.append(document)
    return results


class QueryResult:
    def __init__(self, documents: List[Dict[str, Any]]):
        self.documents = documents

    def sort(self, key: str, direction: int):
        reverse = direction == DESCENDING
        self.documents.sort(key=lambda item: get_nested(item, key) if get_nested(item, key) is not None else '', reverse=reverse)
        return self

    def limit(self, count: int):
        self.documents = self.documents[:count]
        return self

    def __iter__(self):
        return iter(self.documents)

    def __len__(self):
        return len(self.documents)


class SQLiteCollectionBase:
    def __init__(self, conn: sqlite3.Connection, lock: threading.Lock):
        self.conn = conn
        self.lock = lock

    def create_index(self, *args, **kwargs):
        del args, kwargs
        return None


class SQLiteConfigCollection(SQLiteCollectionBase):
    def _load_all(self) -> List[Dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute('SELECT data_json FROM configs').fetchall()
        return [deserialize_storage_value(json.loads(row['data_json'])) for row in rows]

    def find(self, query: Dict[str, Any]):
        return QueryResult(filter_documents(self._load_all(), query))

    def find_one(self, query: Dict[str, Any]):
        docs = filter_documents(self._load_all(), query)
        return docs[0] if docs else None

    def insert_one(self, document: Dict[str, Any]):
        payload = json.dumps(serialize_storage_value(document), ensure_ascii=False)
        try:
            with self.lock:
                self.conn.execute(
                    'INSERT INTO configs(domain, enabled, updated_at, data_json) VALUES (?, ?, ?, ?)',
                    (document['domain'], 1 if document.get('enabled', True) else 0, isoformat(document.get('updated_at')), payload),
                )
                self.conn.commit()
        except sqlite3.IntegrityError as exc:
            raise DuplicateKeyError(str(exc)) from exc
        return SimpleResult(inserted_id=document['domain'])

    def find_one_and_update(self, query: Dict[str, Any], update: Dict[str, Any], upsert=False, return_document=ReturnDocument.BEFORE):
        existing = self.find_one(query)
        if existing is None and not upsert:
            return None
        if existing is None:
            document = dict(query)
            for key, value in update.get('$setOnInsert', {}).items():
                document[key] = value
        else:
            document = dict(existing)
        for key, value in update.get('$set', {}).items():
            document[key] = value
        if existing is None:
            document.setdefault('enabled', True)
        payload = json.dumps(serialize_storage_value(document), ensure_ascii=False)
        with self.lock:
            self.conn.execute(
                'INSERT INTO configs(domain, enabled, updated_at, data_json) VALUES (?, ?, ?, ?) '
                'ON CONFLICT(domain) DO UPDATE SET enabled=excluded.enabled, updated_at=excluded.updated_at, data_json=excluded.data_json',
                (document['domain'], 1 if document.get('enabled', True) else 0, isoformat(document.get('updated_at')), payload),
            )
            self.conn.commit()
        if return_document == ReturnDocument.AFTER:
            return document
        return existing

    def delete_one(self, query: Dict[str, Any]):
        domain = query.get('domain')
        with self.lock:
            cursor = self.conn.execute('DELETE FROM configs WHERE domain = ?', (domain,))
            self.conn.commit()
        return SimpleResult(deleted_count=cursor.rowcount)


class SQLiteRecordCollection(SQLiteCollectionBase):
    def _load_all(self) -> List[Dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute('SELECT id, data_json FROM records').fetchall()
        docs = []
        for row in rows:
            document = deserialize_storage_value(json.loads(row['data_json']))
            document['_id'] = row['id']
            docs.append(document)
        return docs

    def insert_one(self, document: Dict[str, Any]):
        payload = json.dumps(serialize_storage_value(document), ensure_ascii=False)
        with self.lock:
            cursor = self.conn.execute(
                'INSERT INTO records(created_at, request_domain, request_ip, matched_domain, route_applied, data_json) VALUES (?, ?, ?, ?, ?, ?)',
                (
                    isoformat(document['created_at']),
                    document.get('request_domain'),
                    document.get('request_ip'),
                    document.get('matched_domain'),
                    1 if document.get('status', {}).get('route_applied') else 0,
                    payload,
                ),
            )
            self.conn.commit()
            inserted_id = cursor.lastrowid
        return SimpleResult(inserted_id=inserted_id)

    def find(self, query: Dict[str, Any]):
        return QueryResult(filter_documents(self._load_all(), query))

    def find_one(self, query: Dict[str, Any]):
        docs = filter_documents(self._load_all(), query)
        return docs[0] if docs else None


class SQLiteStatsCollection(SQLiteCollectionBase):
    def _load_all(self) -> List[Dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute('SELECT data_json FROM record_stats').fetchall()
        return [deserialize_storage_value(json.loads(row['data_json'])) for row in rows]

    def update_one(self, query: Dict[str, Any], update: Dict[str, Any], upsert=False):
        del upsert
        existing = None
        for item in self._load_all():
            if item['domain'] == query['domain'] and item['minute_bucket'] == query['minute_bucket'] and item['node_id'] == query['node_id']:
                existing = item
                break
        if existing is None:
            document = {
                'domain': query['domain'],
                'minute_bucket': query['minute_bucket'],
                'node_id': query['node_id'],
                'query_count': 0,
                'route_apply_count': 0,
                'ipv4_answer_count': 0,
                'ipv6_answer_count': 0,
            }
            for key, value in update.get('$setOnInsert', {}).items():
                document[key] = value
        else:
            document = dict(existing)
        for key, value in update.get('$inc', {}).items():
            document[key] = document.get(key, 0) + value
        for key, value in update.get('$set', {}).items():
            document[key] = value
        payload = json.dumps(serialize_storage_value(document), ensure_ascii=False)
        with self.lock:
            self.conn.execute(
                'INSERT INTO record_stats(domain, minute_bucket, node_id, last_seen_at, data_json) VALUES (?, ?, ?, ?, ?) '
                'ON CONFLICT(domain, minute_bucket, node_id) DO UPDATE SET last_seen_at=excluded.last_seen_at, data_json=excluded.data_json',
                (
                    document['domain'],
                    isoformat(document['minute_bucket']),
                    document['node_id'],
                    isoformat(document.get('last_seen_at')),
                    payload,
                ),
            )
            self.conn.commit()

    def aggregate(self, pipeline: List[Dict[str, Any]]):
        docs = self._load_all()
        for step in pipeline:
            if '$match' in step:
                docs = filter_documents(docs, step['$match'])
            elif '$group' in step:
                group_spec = step['$group']
                grouped = {}
                for doc in docs:
                    key_spec = group_spec['_id']
                    if isinstance(key_spec, str) and key_spec.startswith('$'):
                        group_key = doc[key_spec[1:]]
                    else:
                        bucket_expr = key_spec['bucket']['$dateTrunc']
                        unit = bucket_expr['unit']
                        bucket_value = truncate_datetime(doc['minute_bucket'], unit)
                        group_key = {'domain': doc['domain'], 'bucket': bucket_value}
                    bucket = json.dumps(serialize_storage_value(group_key), sort_keys=True)
                    if bucket not in grouped:
                        grouped[bucket] = {'_id': group_key}
                        for field in group_spec.keys():
                            if field == '_id':
                                continue
                            if '$sum' in group_spec[field]:
                                grouped[bucket][field] = 0
                            elif '$max' in group_spec[field]:
                                grouped[bucket][field] = None
                    for field, expr in group_spec.items():
                        if field == '_id':
                            continue
                        if '$sum' in expr:
                            source = expr['$sum'][1:]
                            grouped[bucket][field] += doc.get(source, 0)
                        elif '$max' in expr:
                            source = expr['$max'][1:]
                            value = doc.get(source)
                            if grouped[bucket][field] is None or (value is not None and value > grouped[bucket][field]):
                                grouped[bucket][field] = value
                docs = list(grouped.values())
            elif '$sort' in step:
                sort_spec = step['$sort']
                for key, direction in reversed(list(sort_spec.items())):
                    reverse = direction == DESCENDING
                    docs.sort(key=lambda item: get_nested(item, key) if get_nested(item, key) is not None else '', reverse=reverse)
            elif '$limit' in step:
                docs = docs[:step['$limit']]
        return docs


def truncate_datetime(value: datetime, unit: str) -> datetime:
    value = parse_datetime(value)
    if unit == 'minute':
        return value.replace(second=0, microsecond=0)
    if unit == 'hour':
        return value.replace(minute=0, second=0, microsecond=0)
    if unit == 'day':
        return value.replace(hour=0, minute=0, second=0, microsecond=0)
    raise ValueError(f'unsupported unit: {unit}')


def add_dns_record_to_db(record_collection, stats_collection, dns_request, domain_config, route_actions, parsed=True, error=None):
    if record_collection is None or stats_collection is None:
        return None
    document = normalize_dns_request(dns_request, domain_config, route_actions, parsed=parsed, error=error)
    inserted = record_collection.insert_one(document)

    bucket = document['created_at'].replace(second=0, microsecond=0)
    stats_collection.update_one(
        {
            'domain': document['request_domain'] or '*',
            'minute_bucket': bucket,
            'node_id': document['node_id'],
        },
        {
            '$inc': {
                'query_count': 1,
                'route_apply_count': sum(1 for action in route_actions if action.get('status') == 'applied'),
                'ipv4_answer_count': len(document['ipv4']) + len(document['ipv4_net']),
                'ipv6_answer_count': len(document['ipv6']) + len(document['ipv6_net']),
            },
            '$set': {'last_seen_at': document['created_at']},
            '$setOnInsert': {'created_at': document['created_at']},
        },
        upsert=True,
    )
    return str(inserted.inserted_id)


def persist_dns_event(raw_request, domain_config, route_actions, parsed=True, error=None):
    if not state.db_available or state.record_collection is None or state.stats_collection is None:
        return None
    try:
        return add_dns_record_to_db(
            state.record_collection,
            state.stats_collection,
            raw_request,
            domain_config,
            route_actions,
            parsed=parsed,
            error=error,
        )
    except Exception as exc:
        logging.error('failed to persist dns event: %s', exc)
        state.set_error(str(exc))
        disable_sqlite(str(exc))
        return None


def process_dns_request(dns_request_json):
    global system_default_gw, system_default_ipv6_gw
    state.touch_request()
    try:
        dns_request = json.loads(dns_request_json)
        logging.debug('recv a dns request: %s', dns_request)
        if 'request-domain' in dns_request.keys():
            dns_request['request-domain'] = normalize_domain(dns_request['request-domain'])
            domain_config = get_domain_config(dns_request['request-domain'], state.config_cache)
        elif 'request-ip' in dns_request.keys():
            domain_config = {'domain': '*', 'ipv4_gw': system_default_gw, 'ipv6_gw': system_default_ipv6_gw}
            dns_request['request-domain'] = '*'
        else:
            raise ValueError(f'unsupport request type: {dns_request}')

        if domain_config is None and state.args.default:
            domain_config = {
                'domain': dns_request.get('request-domain', '*'),
                'ipv4_gw': system_default_gw,
                'ipv6_gw': system_default_ipv6_gw,
            }

        route_actions = []
        if domain_config is not None:
            route_actions = add_static_route(dns_request, domain_config)
        persist_dns_event(dns_request, domain_config, route_actions)
    except Exception as exc:
        logging.error('Error happened: %s --> %s', exc.__class__.__name__, str(exc))
        state.set_error(str(exc))
        try:
            raw_request = json.loads(dns_request_json)
        except Exception:
            raw_request = {'raw_payload': dns_request_json}
        persist_dns_event(raw_request, None, [], parsed=False, error=str(exc))


def read_config_collection(args, config_collection):
    del args
    if config_collection is None:
        return []
    configs = []
    cursor = config_collection.find({'enabled': True}).sort('domain', ASCENDING)
    for item in cursor:
        configs.append({
            'domain': item['domain'],
            'ipv4_gw': item.get('ipv4_gw'),
            'ipv6_gw': item.get('ipv6_gw'),
            'enabled': item.get('enabled', True),
            'source': item.get('source', 'sqlite'),
            'comment': item.get('comment'),
            'created_at': item.get('created_at'),
            'updated_at': item.get('updated_at'),
        })
    return configs


def read_config_from_dnsmasq(dnsmasq_config_dir):
    config_array = []
    gw = get_default_ipv4_gw()
    for root, folders, files in os.walk(dnsmasq_config_dir):
        del folders
        for file in files:
            conf_file = os.path.join(root, file)
            if file.endswith('.conf'):
                with open(conf_file, encoding='utf-8') as pfile:
                    for line in pfile.readlines():
                        line = line.strip()
                        if re.match(r'\s*#', line) is not None:
                            continue
                        host = re.findall(r'\s*server\s*=\s*/([^/]+)/.*', line)
                        if len(host) == 0:
                            continue
                        host = normalize_domain(host[0])
                        config_array.append({
                            'domain': host,
                            'ipv4_gw': gw,
                            'ipv6_gw': system_default_ipv6_gw,
                            'enabled': True,
                            'source': 'dnsmasq-import',
                            'comment': f'imported from {conf_file}',
                        })
    return config_array


def vtysh_clear_all_static_route(dns_ip):
    logging.info('Start clear all static route, except dns: %s/32', dns_ip)
    dns_net = (dns_ip + '/32', get_default_ipv4_gw())
    static_net_list = vtysh_list_static_route()
    for static_net in list(static_net_list):
        if dns_net == static_net:
            static_net_list.remove(static_net)
            break
    if static_net_list:
        vtysh_ipv4_remove_multi_static_rotue(static_net_list)
    return static_net_list


def convert_config_hashset(config):
    return [str(x) for x in config]


def load_config_into_cache():
    if state.config_collection is None:
        return []
    new_config = read_config_collection(state.args, state.config_collection)
    write_marker = config_rw_lock.gen_wlock()
    write_marker.acquire()
    try:
        state.config_cache.clear()
        state.config_cache.extend(new_config)
    finally:
        write_marker.release()
    return new_config


def cleanup_expired_records(record_ttl_days: int):
    if state.db_client is None:
        return
    cutoff = isoformat(utcnow() - timedelta(days=record_ttl_days))
    with state.db_lock:
        state.db_client.conn.execute('DELETE FROM records WHERE created_at < ?', (cutoff,))
        state.db_client.conn.execute('DELETE FROM record_stats WHERE minute_bucket < ?', (cutoff,))
        state.db_client.conn.commit()


def update_config_timer():
    config_hashset = convert_config_hashset(state.config_cache)
    while not state.stop_event.wait(state.config_refresh_interval):
        try:
            if not state.db_available:
                ensure_sqlite_connection(state.args.sqlite, state.args.record_ttl_days)
                if not state.db_available:
                    continue
            cleanup_expired_records(state.args.record_ttl_days)
            new_config = read_config_collection(state.args, state.config_collection)
            new_config_hashset = convert_config_hashset(new_config)
            differ = set(config_hashset) ^ set(new_config_hashset)
            if len(differ) == 0:
                continue
            write_marker = config_rw_lock.gen_wlock()
            write_marker.acquire()
            try:
                logging.info('config update, differ: %s, before: %s, after: %s', len(differ), len(config_hashset), len(new_config_hashset))
                state.config_cache.clear()
                state.config_cache.extend(new_config)
                config_hashset = new_config_hashset
            finally:
                write_marker.release()
        except Exception as exc:
            logging.error('config refresh failed: %s', exc)
            state.set_error(str(exc))
            disable_sqlite(str(exc))


def config_dns_route(dns_ip):
    vtysh_ipv4_add_one_static_route(dns_ip + '/32', get_default_ipv4_gw())


def parse_socket_url(socket_proto_url: str) -> Tuple[str, str, int]:
    socket_proto = re.findall(r'\s*(.+)://\d+\.\d+\.\d+\.\d+', socket_proto_url)
    if len(socket_proto) != 1:
        raise ValueError(f'failed to parse socket proto url: {socket_proto_url}, proto error')
    socket_proto = socket_proto[0]
    socket_addr = re.findall(r'\s*.+://(\d+\.\d+\.\d+\.\d+)', socket_proto_url)
    if len(socket_addr) != 1:
        raise ValueError(f'failed to parse socket proto url: {socket_proto_url}, addr error')
    socket_addr = socket_addr[0]
    socket_port = re.findall(r'\s*.+://\d+\.\d+\.\d+\.\d+:(\d+)', socket_proto_url)
    socket_port = int(socket_port[0]) if len(socket_port) == 1 else 34321
    return socket_proto, socket_addr, socket_port


def socket_server_loop():
    if state.args.socket is None:
        return
    socket_proto, socket_addr, socket_port = parse_socket_url(state.args.socket)
    logging.info('Start socket server: proto: %s, addr: %s, port: %s', socket_proto, socket_addr, socket_port)
    if socket_proto != 'udp':
        raise RuntimeError(f'current not support socket proto: {state.args.socket}')

    server_socket_fd = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    server_socket_fd.bind((socket_addr, socket_port))
    server_socket_fd.settimeout(1.0)
    try:
        while not state.stop_event.is_set():
            try:
                bytes_address_pair = server_socket_fd.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            message = bytes_address_pair[0]
            try:
                payload = message.decode('utf-8')
            except Exception:
                logging.error('invalid utf-8 payload from udp socket')
                continue
            process_dns_request(payload)
    finally:
        server_socket_fd.close()


def connect_to_sqlite(path, record_ttl_days):
    del record_ttl_days
    sqlite_dir = os.path.dirname(path)
    if sqlite_dir:
        os.makedirs(sqlite_dir, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute(
        'CREATE TABLE IF NOT EXISTS configs ('
        'domain TEXT PRIMARY KEY, '
        'enabled INTEGER NOT NULL, '
        'updated_at TEXT, '
        'data_json TEXT NOT NULL)'
    )
    conn.execute(
        'CREATE TABLE IF NOT EXISTS records ('
        'id INTEGER PRIMARY KEY AUTOINCREMENT, '
        'created_at TEXT NOT NULL, '
        'request_domain TEXT, '
        'request_ip TEXT, '
        'matched_domain TEXT, '
        'route_applied INTEGER NOT NULL, '
        'data_json TEXT NOT NULL)'
    )
    conn.execute(
        'CREATE TABLE IF NOT EXISTS record_stats ('
        'domain TEXT NOT NULL, '
        'minute_bucket TEXT NOT NULL, '
        'node_id TEXT NOT NULL, '
        'last_seen_at TEXT, '
        'data_json TEXT NOT NULL, '
        'PRIMARY KEY(domain, minute_bucket, node_id))'
    )
    conn.execute(
        'CREATE TABLE IF NOT EXISTS meta ('
        'key TEXT PRIMARY KEY, '
        'value TEXT NOT NULL, '
        'updated_at TEXT NOT NULL)'
    )
    conn.execute('CREATE INDEX IF NOT EXISTS idx_records_created_at ON records(created_at)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_records_request_domain ON records(request_domain, created_at)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_records_matched_domain ON records(matched_domain, created_at)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_records_request_ip ON records(request_ip, created_at)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_stats_minute_bucket ON record_stats(minute_bucket)')
    conn.commit()
    client = SQLiteClient(conn)
    return (
        client,
        SQLiteRecordCollection(conn, state.db_lock),
        SQLiteConfigCollection(conn, state.db_lock),
        SQLiteStatsCollection(conn, state.db_lock),
        None,
    )


def disable_sqlite(reason: str):
    if state.db_client is not None:
        try:
            state.db_client.close()
        except Exception:
            pass
    state.db_client = None
    state.record_collection = None
    state.config_collection = None
    state.stats_collection = None
    state.meta_collection = None
    state.set_db_state(False, reason)


def ensure_sqlite_connection(path, record_ttl_days):
    if state.db_client is not None and state.db_available:
        try:
            state.db_client.admin.command('ping')
            return True
        except Exception as exc:
            logging.error('sqlite ping failed, switch to degraded mode: %s', exc)
            disable_sqlite(str(exc))
    try:
        (
            state.db_client,
            state.record_collection,
            state.config_collection,
            state.stats_collection,
            state.meta_collection,
        ) = connect_to_sqlite(path, record_ttl_days)
        state.set_db_state(True, None)
        cleanup_expired_records(record_ttl_days)
        load_config_into_cache()
        logging.info('sqlite connected: %s', path)
        return True
    except Exception as exc:
        logging.error('failed to connect sqlite, degraded mode without recording: %s', exc)
        disable_sqlite(str(exc))
        return False


def process_ip_file(ip_file):
    logging.info('process ip file: %s', ip_file)
    ipv4_gw = get_default_ipv4_gw()
    with open(ip_file, encoding='utf-8') as file_obj:
        for line in file_obj.readlines():
            line = line.strip()
            if line.startswith('#') or len(line) == 0:
                continue
            if re.match(r'\d+\.\d+\.\d+\.\d+/\d+', line) is not None:
                vtysh_ipv4_add_one_static_route(line, ipv4_gw)
                logging.info('add static ip net from ip file: %s -- %s,%s', ip_file, line, ipv4_gw)


def process_extra_ip(args):
    if args.extra is not None and len(args.extra) != 0:
        if not os.path.exists(args.extra):
            logging.error('failed to open extra file, not exist: %s, ignore it', args.extra)
            return
        if os.path.isfile(args.extra):
            process_ip_file(args.extra)
        elif os.path.isdir(args.extra):
            for file in os.listdir(args.extra):
                ip_file = os.path.join(args.extra, file)
                if os.path.isfile(ip_file):
                    process_ip_file(ip_file)


def import_dnsmasq_configs(directory: str) -> Dict[str, int]:
    records = read_config_from_dnsmasq(directory)
    inserted = 0
    updated = 0
    for item in records:
        now = utcnow()
        document = {
            'domain': item['domain'],
            'ipv4_gw': item.get('ipv4_gw'),
            'ipv6_gw': item.get('ipv6_gw'),
            'enabled': item.get('enabled', True),
            'source': item.get('source', 'dnsmasq-import'),
            'comment': item.get('comment'),
            'updated_at': now,
        }
        result = state.config_collection.find_one_and_update(
            {'domain': item['domain']},
            {'$set': document, '$setOnInsert': {'created_at': now}},
            upsert=True,
            return_document=ReturnDocument.BEFORE,
        )
        if result is None:
            inserted += 1
        else:
            updated += 1
    load_config_into_cache()
    return {'inserted': inserted, 'updated': updated, 'total': len(records)}


def document_to_jsonable(document: Dict[str, Any]) -> Dict[str, Any]:
    result = {}
    for key, value in document.items():
        if key == '_id':
            result['id'] = str(value)
        elif isinstance(value, datetime):
            result[key] = isoformat(value)
        elif isinstance(value, list):
            result[key] = [document_to_jsonable(item) if isinstance(item, dict) else isoformat(item) if isinstance(item, datetime) else item for item in value]
        elif isinstance(value, dict):
            result[key] = document_to_jsonable(value)
        else:
            result[key] = value
    return result


def api_error(code: str, message: str, details: Optional[Any] = None, status_code: int = 400):
    payload = {'code': code, 'message': message, 'details': details}
    return JSONResponse(status_code=status_code, content=payload)


class ConfigPayload(BaseModel):
    if ConfigDict is not None:
        model_config = ConfigDict(extra='forbid')

    domain: str = Field(..., min_length=1)
    ipv4_gw: Optional[str] = None
    ipv6_gw: Optional[str] = None
    enabled: bool = True
    source: str = 'api'
    comment: Optional[str] = None

    if field_validator is not None:
        @field_validator('domain')
        @classmethod
        def validate_domain(cls, value: str):
            return normalize_domain(value)

        @field_validator('ipv4_gw')
        @classmethod
        def validate_ipv4_gw(cls, value: Optional[str]):
            return validate_ipv4(value)

        @field_validator('ipv6_gw')
        @classmethod
        def validate_ipv6_gw(cls, value: Optional[str]):
            return validate_ipv6(value)


class ImportPayload(BaseModel):
    if ConfigDict is not None:
        model_config = ConfigDict(extra='forbid')

    directory: str = '/etc/dnsmasq.d/'


class RouteClearPayload(BaseModel):
    if ConfigDict is not None:
        model_config = ConfigDict(extra='forbid')

    dns_ip: Optional[str] = None


async def verify_token(authorization: Optional[str] = Header(default=None)):
    if state.api_token_hash is None:
        return True
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(status_code=401, detail='missing bearer token')
    token = authorization[7:]
    if hash_token(token) != state.api_token_hash:
        raise HTTPException(status_code=401, detail='invalid token')
    return True


async def sqlite_guard():
    if not state.db_available or state.db_client is None:
        raise HTTPException(status_code=503, detail=f"sqlite unavailable: {state.db_disabled_reason or 'degraded mode'}")
    try:
        state.db_client.admin.command('ping')
    except Exception as exc:
        disable_sqlite(str(exc))
        raise HTTPException(status_code=503, detail=f'sqlite unavailable: {exc}') from exc
    return True


def create_api_app():
    ensure_fastapi_installed()
    app = FastAPI(title='smartdns-server', version='1.0.0')

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        del request
        return api_error('http_error', str(exc.detail), status_code=exc.status_code)

    @app.exception_handler(DuplicateKeyError)
    async def duplicate_handler(request: Request, exc: DuplicateKeyError):
        del request
        return api_error('duplicate_key', 'resource already exists', str(exc), status_code=409)

    @app.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc: Exception):
        del request
        logging.exception('unhandled api exception')
        return api_error('internal_error', 'internal server error', str(exc), status_code=500)

    @app.get('/healthz')
    async def healthz():
        return {'status': 'ok', 'time': isoformat(utcnow()), 'sqlite_available': state.db_available}

    @app.get('/api/v1/status', dependencies=[Depends(verify_token)])
    async def get_status():
        return {
            'sqlite': {
                'available': state.db_available,
                'reason': state.db_disabled_reason,
                'path': state.args.sqlite,
            },
            'config_count': len(state.config_cache),
            'last_request_at': isoformat(state.last_request_at),
            'last_error': state.last_error,
            'default_ipv4_gw': system_default_gw,
            'default_ipv6_gw': system_default_ipv6_gw,
            'threads': {
                'socket_thread_alive': state.socket_thread.is_alive() if state.socket_thread else False,
                'api_thread_alive': state.api_thread.is_alive() if state.api_thread else False,
            },
        }

    @app.get('/api/v1/configs', dependencies=[Depends(verify_token), Depends(sqlite_guard)])
    async def list_configs(enabled: Optional[bool] = None):
        query = {}
        if enabled is not None:
            query['enabled'] = enabled
        items = [document_to_jsonable(item) for item in state.config_collection.find(query).sort('domain', ASCENDING)]
        return {'items': items}

    @app.post('/api/v1/configs', dependencies=[Depends(verify_token), Depends(sqlite_guard)])
    async def create_config(payload: ConfigPayload):
        now = utcnow()
        document = payload.model_dump()
        document['created_at'] = now
        document['updated_at'] = now
        state.config_collection.insert_one(document)
        load_config_into_cache()
        return {'item': document_to_jsonable(document)}

    @app.get('/api/v1/configs/{domain}', dependencies=[Depends(verify_token), Depends(sqlite_guard)])
    async def get_config(domain: str):
        normalized = normalize_domain(domain)
        item = state.config_collection.find_one({'domain': normalized})
        if item is None:
            raise HTTPException(status_code=404, detail='config not found')
        return {'item': document_to_jsonable(item)}

    @app.put('/api/v1/configs/{domain}', dependencies=[Depends(verify_token), Depends(sqlite_guard)])
    async def update_config(domain: str, payload: ConfigPayload):
        normalized = normalize_domain(domain)
        if payload.domain != normalized:
            raise HTTPException(status_code=400, detail='path domain and payload domain mismatch')
        updated = state.config_collection.find_one_and_update(
            {'domain': normalized},
            {'$set': {**payload.model_dump(), 'updated_at': utcnow()}},
            return_document=ReturnDocument.AFTER,
        )
        if updated is None:
            raise HTTPException(status_code=404, detail='config not found')
        load_config_into_cache()
        return {'item': document_to_jsonable(updated)}

    @app.delete('/api/v1/configs/{domain}', dependencies=[Depends(verify_token), Depends(sqlite_guard)])
    async def delete_config(domain: str):
        normalized = normalize_domain(domain)
        result = state.config_collection.delete_one({'domain': normalized})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail='config not found')
        load_config_into_cache()
        return {'deleted': True, 'domain': normalized}

    @app.post('/api/v1/configs/import-dnsmasq', dependencies=[Depends(verify_token), Depends(sqlite_guard)])
    async def import_configs(payload: ImportPayload):
        result = import_dnsmasq_configs(payload.directory)
        return result

    @app.post('/api/v1/configs/reload', dependencies=[Depends(verify_token), Depends(sqlite_guard)])
    async def reload_configs():
        configs = load_config_into_cache()
        return {'reloaded': len(configs)}

    @app.get('/api/v1/records', dependencies=[Depends(verify_token), Depends(sqlite_guard)])
    async def list_records(
        domain: Optional[str] = None,
        request_ip: Optional[str] = None,
        matched_domain: Optional[str] = None,
        from_time: Optional[str] = Query(default=None, alias='from'),
        to_time: Optional[str] = Query(default=None, alias='to'),
        limit: int = Query(default=50, ge=1, le=200),
        cursor: Optional[str] = None,
    ):
        query: Dict[str, Any] = {}
        if domain:
            query['request_domain'] = normalize_domain(domain)
        if request_ip:
            query['request_ip'] = request_ip
        if matched_domain:
            query['matched_domain'] = normalize_domain(matched_domain)
        time_query = {}
        if from_time:
            time_query['$gte'] = parse_datetime(from_time)
        if to_time:
            time_query['$lte'] = parse_datetime(to_time)
        if time_query:
            query['created_at'] = time_query
        if cursor:
            query['_id'] = {'$lt': int(cursor)}
        docs = list(state.record_collection.find(query).sort('_id', DESCENDING).limit(limit + 1))
        next_cursor = None
        if len(docs) > limit:
            next_cursor = str(docs[limit - 1]['_id'])
            docs = docs[:limit]
        return {'items': [document_to_jsonable(item) for item in docs], 'next_cursor': next_cursor}

    @app.get('/api/v1/records/{record_id}', dependencies=[Depends(verify_token), Depends(sqlite_guard)])
    async def get_record(record_id: str):
        doc = state.record_collection.find_one({'_id': int(record_id)})
        if doc is None:
            raise HTTPException(status_code=404, detail='record not found')
        return {'item': document_to_jsonable(doc)}

    @app.get('/api/v1/stats/domains', dependencies=[Depends(verify_token), Depends(sqlite_guard)])
    async def get_domain_stats(
        domain: Optional[str] = None,
        from_time: Optional[str] = Query(default=None, alias='from'),
        to_time: Optional[str] = Query(default=None, alias='to'),
        bucket: str = Query(default='minute', pattern='^(minute|hour|day)$'),
    ):
        match: Dict[str, Any] = {}
        if domain:
            match['domain'] = normalize_domain(domain)
        time_query = {}
        if from_time:
            time_query['$gte'] = parse_datetime(from_time)
        if to_time:
            time_query['$lte'] = parse_datetime(to_time)
        if time_query:
            match['minute_bucket'] = time_query
        pipeline = []
        if match:
            pipeline.append({'$match': match})
        pipeline.extend([
            {'$group': {
                '_id': {
                    'domain': '$domain',
                    'bucket': {'$dateTrunc': {'date': '$minute_bucket', 'unit': bucket}},
                },
                'query_count': {'$sum': '$query_count'},
                'route_apply_count': {'$sum': '$route_apply_count'},
                'ipv4_answer_count': {'$sum': '$ipv4_answer_count'},
                'ipv6_answer_count': {'$sum': '$ipv6_answer_count'},
                'last_seen_at': {'$max': '$last_seen_at'},
            }},
            {'$sort': {'_id.bucket': DESCENDING, '_id.domain': ASCENDING}},
        ])
        docs = list(state.stats_collection.aggregate(pipeline))
        items = []
        for item in docs:
            items.append({
                'domain': item['_id']['domain'],
                'bucket': isoformat(item['_id']['bucket']),
                'query_count': item['query_count'],
                'route_apply_count': item['route_apply_count'],
                'ipv4_answer_count': item['ipv4_answer_count'],
                'ipv6_answer_count': item['ipv6_answer_count'],
                'last_seen_at': isoformat(item.get('last_seen_at')),
            })
        return {'items': items}

    @app.get('/api/v1/stats/top-domains', dependencies=[Depends(verify_token), Depends(sqlite_guard)])
    async def get_top_domains(
        from_time: Optional[str] = Query(default=None, alias='from'),
        to_time: Optional[str] = Query(default=None, alias='to'),
        limit: int = Query(default=20, ge=1, le=100),
    ):
        match: Dict[str, Any] = {}
        time_query = {}
        if from_time:
            time_query['$gte'] = parse_datetime(from_time)
        if to_time:
            time_query['$lte'] = parse_datetime(to_time)
        if time_query:
            match['minute_bucket'] = time_query
        pipeline = []
        if match:
            pipeline.append({'$match': match})
        pipeline.extend([
            {'$group': {
                '_id': '$domain',
                'query_count': {'$sum': '$query_count'},
                'route_apply_count': {'$sum': '$route_apply_count'},
                'last_seen_at': {'$max': '$last_seen_at'},
            }},
            {'$sort': {'query_count': DESCENDING, '_id': ASCENDING}},
            {'$limit': limit},
        ])
        docs = list(state.stats_collection.aggregate(pipeline))
        return {'items': [
            {
                'domain': item['_id'],
                'query_count': item['query_count'],
                'route_apply_count': item['route_apply_count'],
                'last_seen_at': isoformat(item.get('last_seen_at')),
            }
            for item in docs
        ]}

    @app.get('/api/v1/routes', dependencies=[Depends(verify_token)])
    async def list_routes():
        routes = vtysh_list_static_route()
        return {'items': [{'target': target, 'gateway': gateway} for target, gateway in routes]}

    @app.post('/api/v1/routes/clear', dependencies=[Depends(verify_token)])
    async def clear_routes(payload: RouteClearPayload):
        dns_ip = payload.dns_ip or state.args.dns
        cleared = vtysh_clear_all_static_route(dns_ip)
        return {'cleared': [{'target': target, 'gateway': gateway} for target, gateway in cleared], 'kept_dns_ip': dns_ip}

    @app.post('/api/v1/routes/reapply', dependencies=[Depends(verify_token), Depends(sqlite_guard)])
    async def reapply_routes():
        applied = []
        cursor = state.record_collection.find({'matched_domain': {'$ne': None}, 'status.route_applied': True}).sort('created_at', DESCENDING).limit(200)
        for record in cursor:
            raw_request = record.get('raw_request') or {}
            request_domain = raw_request.get('request-domain')
            if request_domain:
                request_domain = normalize_domain(request_domain)
            config = get_domain_config(request_domain, state.config_cache) if request_domain and request_domain != '*' else None
            if config is None and record.get('matched_domain'):
                config = next((item for item in state.config_cache if item['domain'] == record['matched_domain']), None)
            if config is None:
                continue
            route_actions = add_static_route(raw_request, config)
            applied.append({'request_domain': request_domain, 'matched_domain': config['domain'], 'route_actions': route_actions})
        return {'items': applied}

    return app


def api_server_loop():
    app = create_api_app()
    config = uvicorn.Config(app, host=state.args.api_host, port=state.args.api_port, log_level='info')
    server = uvicorn.Server(config)
    server.run()


def setup_logging(args):
    log_level = logging.DEBUG if args.debug else logging.INFO
    log_formatter = '%(asctime)s [%(threadName)s] [%(levelname)-5.5s]  %(message)s'
    if args.log is not None and len(args.log) != 0:
        file_handler = RotatingFileHandler(args.log, mode='a', maxBytes=5 * 1024 * 1024, backupCount=1, encoding='utf-8', delay=False)
        file_handler.setFormatter(logging.Formatter(log_formatter))
        logging.basicConfig(format=log_formatter, level=log_level, handlers=[file_handler])
    else:
        logging.basicConfig(format=log_formatter, level=log_level, handlers=[logging.StreamHandler(sys.stdout)])
    logging.info('start smartdns-server python server ,log_level: %s', log_level)


def build_arg_parser():
    parser = argparse.ArgumentParser(description='dns_server process.')
    parser.add_argument('--log', metavar='l', type=str, required=False, help='log file')
    parser.add_argument('--sqlite', metavar='s', type=str, required=False, default='/var/lib/smartdns/smartdns.sqlite3', help='sqlite file path')
    parser.add_argument('--node_id', metavar='n', type=str, required=True, help='node id, example: 10.10.8.1')
    parser.add_argument('--dns', metavar='d', type=str, required=True, help='dns IP, example: 8.8.8.8')
    parser.add_argument('--socket', metavar='u', type=str, required=False, help='server proto, current support udp, example: udp://127.0.0.1:1234')
    parser.add_argument('--extra', metavar='e', type=str, required=False, help='extra_ip_net list file')
    parser.add_argument('--debug', action='store_true', help='config if debug')
    parser.add_argument('--default', action='store_true', help='use as all default with any dns request, ignore sqlite config miss')
    parser.add_argument('--clear', action='store_true', help='clear all static route')
    parser.add_argument('--api-host', type=str, default='localhost', help='rest api listen host, default localhost')
    parser.add_argument('--api-port', type=int, default=8080, help='rest api listen port, default 8080')
    parser.add_argument('--api-token', type=str, default=None, help='rest api bearer token')
    parser.add_argument('--record-ttl-days', type=int, default=7, help='dns record ttl days')
    parser.add_argument('--config-refresh-interval', type=int, default=5, help='sqlite config refresh interval seconds')
    parser.add_argument('--import-dnsmasq-dir', type=str, default=None, help='import dnsmasq config dir into sqlite and exit')
    return parser


def install_signal_handlers():
    def handle_signal(signum, frame):
        del frame
        logging.info('received signal %s, shutting down', signum)
        state.stop_event.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)


def main():
    global state, vtysh_console, system_default_gw, system_default_ipv6_gw
    args = build_arg_parser().parse_args()
    setup_logging(args)

    state = AppState(args)
    install_signal_handlers()

    system_default_gw = get_default_ipv4_gw()
    system_default_ipv6_gw = get_default_ipv6_gw()

    ensure_sqlite_connection(args.sqlite, args.record_ttl_days)

    if args.import_dnsmasq_dir:
        if not state.db_available:
            logging.error('cannot import dnsmasq config without sqlite connection')
            return 1
        result = import_dnsmasq_configs(args.import_dnsmasq_dir)
        logging.info('import dnsmasq config result: %s', result)
        return 0

    if args.clear:
        vtysh_console = start_vtysh_console()
        vtysh_clear_all_static_route(args.dns)
        process_extra_ip(args)
        return 0

    vtysh_console = start_vtysh_console()
    process_extra_ip(args)
    config_dns_route(args.dns)

    refresh_thread = threading.Thread(target=update_config_timer, name='config-refresh', daemon=True)
    refresh_thread.start()

    if args.socket is not None:
        state.socket_thread = threading.Thread(target=socket_server_loop, name='udp-socket-server', daemon=True)
        state.socket_thread.start()
    else:
        logging.error('not start any server, you must special socket server proto')
        return 1

    state.api_thread = threading.Thread(target=api_server_loop, name='http-api-server', daemon=True)
    state.api_thread.start()

    try:
        while not state.stop_event.wait(1):
            if state.socket_thread and not state.socket_thread.is_alive():
                logging.error('socket server thread exited unexpectedly')
                return 1
            if state.api_thread and not state.api_thread.is_alive():
                logging.error('api server thread exited unexpectedly')
                return 1
    finally:
        state.stop_event.set()
        if state.db_client is not None:
            state.db_client.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
