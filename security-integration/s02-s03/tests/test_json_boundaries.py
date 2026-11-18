# SPDX-License-Identifier: Apache-2.0
"""Data-only boundary witnesses; no native scanner or execution qualification."""
import unittest
import support
from ocr_security.common import Refusal, canonical
from ocr_security_adapters.data import bounded_json, bounded_ocr_evidence


class JsonBoundaries(unittest.TestCase):
    def rejects(self, raw, code, reader=bounded_json):
        with self.assertRaises(Refusal) as caught:
            reader(raw)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)

    def test_exact_byte_limits(self):
        for reader, limit in ((bounded_json, 1048576), (bounded_ocr_evidence, 8388608)):
            with self.subTest(limit=limit):
                raw=b'0'+b' '*(limit-1)
                self.assertEqual(reader(raw), 0)
                self.rejects(raw+b' ', 'document_limit',reader)

    def test_depth_boundary(self):
        for reader in (bounded_json,bounded_ocr_evidence):
            raw=b'['*32+b'0'+b']'*32
            self.assertIsInstance(reader(raw),list)
            self.rejects(b'['+raw+b']','document_structure_limit',reader)

    def test_container_size_boundaries(self):
        for value in ([0]*4096,{str(i):0 for i in range(4096)}):
            self.assertEqual(bounded_json(canonical(value)),value)
        for value in ([0]*4097,{str(i):0 for i in range(4097)}):
            self.rejects(canonical(value),'document_structure_limit')

    def test_string_and_key_boundaries(self):
        self.assertEqual(bounded_json(canonical('x'*65536)),'x'*65536)
        self.rejects(canonical('x'*65537),'document_string_limit')
        self.assertEqual(bounded_json(canonical({'x'*256:0})),{'x'*256:0})
        self.rejects(canonical({'x'*257:0}),'invalid_key')

    def test_native_node_budget(self):
        # root + 8 containers + 32759 scalar leaves = 32768 nodes
        value=[[0]*4096 for _ in range(7)]+[[0]*4087]
        self.assertEqual(bounded_json(canonical(value)),value)
        value[-1].append(0)
        self.rejects(canonical(value),'document_structure_limit')
        self.assertEqual(bounded_ocr_evidence(canonical(value)),value)

    def test_ocr_node_budget(self):
        # root + 64 containers + 262079 leaves = 262144 nodes
        value=[[0]*4096 for _ in range(63)]+[[0]*4031]
        self.assertEqual(bounded_ocr_evidence(canonical(value)),value)
        value[-1].append(0)
        self.rejects(canonical(value),'document_structure_limit',bounded_ocr_evidence)

    def test_ambiguous_or_invalid_documents(self):
        for reader in (bounded_json,bounded_ocr_evidence):
            for raw in (b'{"a":1,"a":2}',b'{"a":{"b":1,"b":2}}'):
                self.rejects(raw,'duplicate_key',reader)
            for raw in (b'NaN',b'Infinity',b'-Infinity',b'1e999',b'\xff',b'{"private payload":',b'0 1'):
                self.rejects(raw,'invalid_document',reader)
            self.rejects('not bytes','document_limit',reader)

    def test_empty_and_scalar_documents_preserved(self):
        for value in ({},[],None,True,False,0,-1,1.25,'safe'):
            for reader in (bounded_json,bounded_ocr_evidence):
                self.assertEqual(reader(canonical(value)),value)

if __name__=='__main__':
    unittest.main()
