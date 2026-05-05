import importlib.util
import sys
import types
import unittest
from types import SimpleNamespace


class DummyLockHandle:
    def acquire(self):
        return None

    def release(self):
        return None


class DummyRWLock:
    def gen_rlock(self):
        return DummyLockHandle()

    def gen_wlock(self):
        return DummyLockHandle()


class DummyCollection:
    def __init__(self):
        self.inserted = []
        self.updated = []

    def insert_one(self, document):
        self.inserted.append(document)
        return SimpleNamespace(inserted_id='abc123')

    def update_one(self, query, update, upsert=False):
        self.updated.append((query, update, upsert))
        return SimpleNamespace()


class DnsServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class ReaderWriterLockModule(types.ModuleType):
            class rwlock:  # noqa: N801
                @staticmethod
                def RWLockFair():
                    return DummyRWLock()

        sys.modules['readerwriterlock'] = ReaderWriterLockModule('readerwriterlock')
        spec = importlib.util.spec_from_file_location('dns_server', 'dns_server.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls.module = module
        cls.module.config_rw_lock = DummyRWLock()
        cls.module.state = SimpleNamespace(
            args=SimpleNamespace(node_id='node-1'),
            db_available=True,
            record_collection=None,
            stats_collection=None,
            set_error=lambda message: None,
        )

    def test_get_domain_config_exact_and_suffix(self):
        configs = [
            {'domain': 'example.com', 'ipv4_gw': '1.1.1.1', 'ipv6_gw': None},
            {'domain': 'a.example.com', 'ipv4_gw': '2.2.2.2', 'ipv6_gw': None},
        ]
        exact = self.module.get_domain_config('example.com', configs)
        suffix = self.module.get_domain_config('x.a.example.com', configs)
        self.assertEqual(exact['ipv4_gw'], '1.1.1.1')
        self.assertEqual(suffix['ipv4_gw'], '2.2.2.2')

    def test_get_domain_config_none(self):
        configs = [{'domain': 'example.com', 'ipv4_gw': '1.1.1.1', 'ipv6_gw': None}]
        self.assertIsNone(self.module.get_domain_config('other.com', configs))

    def test_add_dns_record_to_db_persists_record_and_stats(self):
        record_collection = DummyCollection()
        stats_collection = DummyCollection()
        dns_request = {
            'request-domain': 'www.example.com',
            'request-ip': '10.0.0.2',
            'ipv4': [{'addr': '1.2.3.4', 'domain': 'www.example.com'}],
            'ipv6': [{'addr': '2001:db8::1', 'domain': 'www.example.com'}],
        }
        domain_config = {'domain': 'example.com', 'ipv4_gw': '1.1.1.1', 'ipv6_gw': '2001:db8::ff'}
        route_actions = [{'family': 'ipv4', 'target': '1.2.3.0/24', 'gateway': '1.1.1.1', 'status': 'applied'}]

        record_id = self.module.add_dns_record_to_db(
            record_collection,
            stats_collection,
            dns_request,
            domain_config,
            route_actions,
        )

        self.assertEqual(record_id, 'abc123')
        self.assertEqual(len(record_collection.inserted), 1)
        document = record_collection.inserted[0]
        self.assertEqual(document['request_domain'], 'www.example.com')
        self.assertEqual(document['matched_domain'], 'example.com')
        self.assertTrue(document['status']['route_applied'])
        self.assertEqual(len(stats_collection.updated), 1)

    def test_persist_dns_event_is_noop_when_sqlite_unavailable(self):
        self.module.state.db_available = False
        self.module.state.record_collection = DummyCollection()
        self.module.state.stats_collection = DummyCollection()
        result = self.module.persist_dns_event(
            {'request-domain': 'www.example.com'},
            {'domain': 'example.com', 'ipv4_gw': '1.1.1.1', 'ipv6_gw': None},
            [],
        )
        self.assertIsNone(result)
        self.assertEqual(self.module.state.record_collection.inserted, [])
        self.module.state.db_available = True


if __name__ == '__main__':
    unittest.main()
