"""EQL validation must measure both corpora and reject incomplete evidence."""

import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'autonomous'))
from orchestration import validation_eql


class EQLValidationTests(unittest.TestCase):
    def setUp(self):
        self.attack = [{"@timestamp": "2026-04-12T10:00:00Z", "event": {"category": "process"}}]
        self.benign = [{"@timestamp": "2026-04-12T09:00:00Z", "event": {"category": "process"}}]
        self.matches = {"attack": 1, "benign": 0}
        self.requests = []
        self.response_edit = None
        self.enterContext(patch.object(validation_eql, '_check_es_reachable', return_value=True))
        self.cleanup = self.enterContext(patch.object(validation_eql, '_cleanup_index'))
        self.request = self.enterContext(patch.object(validation_eql, '_es_request', side_effect=self.es))

    def es(self, url, method='GET', data=None, **kwargs):
        self.requests.append((url, method, data))
        index = url.split('/')[3]
        if method == 'PUT':
            operation, response = 'create', {"acknowledged": True}
        elif url.endswith('/_bulk'):
            operation = 'bulk'
            actions = [json.loads(line)["index"] for line in data.strip().splitlines()[::2]]
            response = {"errors": False, "items": [
                {"index": {"status": 201, "_id": action["_id"]}} for action in actions]}
        elif url.endswith('/_refresh'):
            operation, response = 'refresh', {"_shards": {"total": 1, "successful": 1, "failed": 0}}
        else:
            ids = data['filter']['ids']['values']
            operation = 'attack' if ids[0].startswith('atk-') else 'benign'
            sequences = [{"events": [{"_index": index, "_id": ids[0]}]} for _ in range(self.matches[operation])]
            response = {"is_partial": False, "is_running": False,
                        "hits": {"total": {"relation": "eq", "value": len(sequences)}, "sequences": sequences}}
        if self.response_edit:
            response = self.response_edit(operation, response)
        if isinstance(response, Exception):
            raise response
        return 200, response

    def validate(self, **kwargs):
        return validation_eql.validate_eql_against_elasticsearch(
            'sequence [process where true]', kwargs.pop('attack_events', self.attack),
            kwargs.pop('benign_events', self.benign), es_url='http://localhost:9200',
            es_auth=('elastic', 'test'), **kwargs)

    def test_success_queries_each_population_and_preserves_timestamps(self):
        result = self.validate()
        self.assertEqual(result['errors'], [])
        self.assertEqual((result['tp'], result['fp'], result['fn'], result['tn']), (1, 0, 0, 1))
        self.assertEqual(result['scoring_unit'], 'scenario')
        self.assertEqual((result['total_attack'], result['total_benign']), (1, 1))
        self.assertEqual(result['attack_sequences_found'], 1)
        self.assertEqual(result['benign_sequences_found'], 0)
        queries = [data for url, _, data in self.requests if url.endswith('/_eql/search')]
        self.assertEqual([q['filter']['ids']['values'] for q in queries], [['atk-0'], ['ben-1']])
        bulk = next(data for url, _, data in self.requests if url.endswith('/_bulk'))
        self.assertEqual(json.loads(bulk.splitlines()[1])['@timestamp'], self.attack[0]['@timestamp'])
        self.cleanup.assert_called_once()

    def test_benign_sequence_cannot_satisfy_missing_attack_sequence(self):
        self.matches = {'attack': 0, 'benign': 1}
        result = self.validate()
        self.assertEqual((result['tp'], result['fp'], result['fn'], result['tn']), (0, 1, 1, 0))
        self.assertEqual(result['f1_score'], 0)

    def test_true_and_false_positive_sequences_are_counted_independently(self):
        self.matches = {'attack': 2, 'benign': 1}
        result = self.validate()
        self.assertEqual((result['tp'], result['fp'], result['fn'], result['tn']), (1, 1, 0, 0))
        self.assertEqual(result['f1_score'], .6667)

    def test_extra_attack_sequences_are_not_false_positives(self):
        self.matches['attack'] = 2
        result = self.validate()
        self.assertEqual((result['tp'], result['fp']), (1, 0))
        self.assertEqual(result['f1_score'], 1)

    def test_expected_sequences_minimum_is_enforced(self):
        result = self.validate(expected_sequences=2)
        self.assertEqual((result['tp'], result['fn']), (0, 1))

    def test_untested_benign_population_is_never_a_true_negative(self):
        result = self.validate(benign_events=[])
        self.assertEqual(result['tn'], 0)
        self.assertEqual(result['total_benign'], 0)
        queries = [url for url, _, _ in self.requests if url.endswith('/_eql/search')]
        self.assertEqual(len(queries), 1)

    def test_missing_timestamp_fails_before_index_creation(self):
        result = self.validate(attack_events=[{'event': {'category': 'process'}}])
        self.assertIn('explicit timestamps', result['errors'][0])
        self.assertEqual(self.request.call_count, 0)

    def test_bulk_failure_or_incomplete_items_prevents_queries(self):
        for response in ({'errors': True, 'items': []}, {'errors': False, 'items': []},
                         {'errors': False, 'items': [{'index': {'status': 201}}, {'index': {'status': 400}}]},
                         {'errors': False, 'items': [{'index': {'status': 201}}, {'index': {'status': 201, 'error': 'failed'}}]}):
            with self.subTest(response=response):
                self.requests.clear()
                self.response_edit = lambda op, data: response if op == 'bulk' else data
                result = self.validate()
                self.assertTrue(result['errors'])
                self.assertEqual(result['events_ingested'], 0)
                self.assertFalse(any(url.endswith('/_eql/search') for url, _, _ in self.requests))

    def test_failed_create_or_refresh_is_not_ignored(self):
        for target, change in (('create', {'acknowledged': False}), ('refresh', {'_shards': {'failed': 1}})):
            with self.subTest(target=target):
                self.response_edit = lambda op, data: change if op == target else data
                result = self.validate()
                self.assertTrue(result['errors'])
                self.assertEqual(result['f1_score'], 0)

    def test_refresh_requires_all_shards_and_bulk_requires_expected_ids(self):
        cases = [
            ('refresh', lambda r: {}),
            ('refresh', lambda r: {"_shards": {"total": 1, "successful": 0, "failed": 0}}),
            ('refresh', lambda r: {"_shards": {"total": True, "successful": 1, "failed": 0}}),
            ('bulk', lambda r: {**r, "items": [{"index": {"status": 201}}] + r["items"][1:]}),
            ('bulk', lambda r: {**r, "items": [{"index": {"status": 201, "_id": "wrong"}}] + r["items"][1:]}),
        ]
        for target, alter in cases:
            with self.subTest(target=target, alter=alter):
                self.requests.clear()
                self.response_edit = lambda op, data: alter(data) if op == target else data
                result = self.validate()
                self.assertTrue(result['errors'])
                self.assertEqual(result['f1_score'], 0)
                self.assertFalse(any(url.endswith('/_eql/search') for url, _, _ in self.requests))

    def test_incomplete_or_invalid_query_responses_never_score_success(self):
        alterations = [
            lambda d: {**d, 'is_partial': True},
            lambda d: {**d, 'is_running': True},
            lambda d: {**d, 'timed_out': True},
            lambda d: {**d, '_shards': {'failed': 1}},
            lambda d: {**d, 'error': 'query failed'},
            lambda d: {**d, 'hits': {}},
            lambda d: {**d, 'hits': {**d['hits'], 'total': {'relation': 'gte', 'value': 1}}},
            lambda d: {**d, 'hits': {**d['hits'], 'total': {'relation': 'eq', 'value': 2}}},
            lambda d: {**d, 'hits': {**d['hits'], 'sequences': [{'events': []}]}},
            lambda d: {**d, 'hits': {**d['hits'], 'sequences': [{'events': [{'_id': 'ben-1', '_index': 'other'}]}]}},
        ]
        for alter in alterations:
            with self.subTest(alter=alter):
                self.response_edit = lambda op, data: alter(copy.deepcopy(data)) if op == 'attack' else data
                result = self.validate()
                self.assertTrue(result['errors'])
                self.assertEqual(result['f1_score'], 0)
                self.assertEqual(result['tn'], 0)

    def test_query_limit_is_not_silently_truncated(self):
        self.matches['attack'] = 1000
        result = self.validate()
        self.assertIn('truncated', result['errors'][0])

    def test_benign_query_failure_cannot_leave_perfect_attack_score(self):
        self.response_edit = lambda op, data: RuntimeError('benign query unavailable') if op == 'benign' else data
        result = self.validate()
        self.assertTrue(result['errors'])
        self.assertEqual(result['f1_score'], 0)
        self.assertEqual(result['tn'], 0)

    def test_unreachable_returns_none_without_claiming_evidence(self):
        with patch.object(validation_eql, '_check_es_reachable', return_value=False):
            self.assertIsNone(self.validate())
        self.request.assert_not_called()


if __name__ == '__main__':
    unittest.main()
