# SPDX-License-Identifier: Apache-2.0
"""Inert exact-function test: no asset, snapshot, native or scanner execution.

Only inventory acquisition and Refusal are stubs. The mapper/class/constants are
compiled unmodified from the module AST, so this does not qualify composition.
"""
import ast
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
import os
import unittest


class Refusal(Exception):
    pass


def mapper():
    path = Path(os.environ.get("OSV_SOURCE", str(Path(__file__).parents[1] / "ocr_security_adapters" / "osv.py")))
    tree = ast.parse(path.read_text())
    nodes = [n for n in tree.body if
             isinstance(n, (ast.ClassDef, ast.FunctionDef)) and n.name in ("Lockfile", "lock_inputs")
             or isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "LOCKFILES" for t in n.targets)]
    namespace = {"dataclass": dataclass, "Refusal": Refusal,
                 "scanner_inputs": lambda snapshot: (SimpleNamespace(opaque_id="safe"), SimpleNamespace(opaque_id="second"))}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)
    return namespace


class LockfileFieldTests(unittest.TestCase):
    def setUp(self):
        self.n = mapper()

    def test_malformed_fields_refuse_without_hashing(self):
        class StringSubclass(str):
            __hash__ = None
        values = [None, [], {}, set(), (), 0, True, 1.5, b"safe", StringSubclass("safe")]
        for value in values:
            for lock in (self.n["Lockfile"](value, "npm"), self.n["Lockfile"]("safe", value)):
                with self.subTest(value=repr(value), lock=repr(lock)):
                    with self.assertRaisesRegex(Refusal, "unsupported_lockfile"):
                        self.n["lock_inputs"](None, (lock,))

    def test_supported_formats_keep_exact_mapping(self):
        for fmt, (basename, ecosystem) in self.n["LOCKFILES"].items():
            result = self.n["lock_inputs"](None, (self.n["Lockfile"]("safe", fmt),))
            self.assertEqual(result[0][:2], ("/input/safe/" + basename, ecosystem))
            self.assertEqual(result[0][2].opaque_id, "safe")

    def test_unknown_and_duplicate_refuse(self):
        for locks in [(self.n["Lockfile"]("missing", "npm"),), (self.n["Lockfile"]("safe", "unknown"),),
                      (self.n["Lockfile"]("safe", "npm"), self.n["Lockfile"]("safe", "yarn")), (object(),)]:
            with self.assertRaisesRegex(Refusal, "unsupported_lockfile"):
                self.n["lock_inputs"](None, locks)

    def test_selection_shape_limit_preserved(self):
        for selection in [None, [], (), (self.n["Lockfile"]("safe", "npm"),) * 257]:
            with self.assertRaisesRegex(Refusal, "invalid_lockfile_selection"):
                self.n["lock_inputs"](None, selection)

    def test_distinct_selection_order_preserved(self):
        result = self.n["lock_inputs"](None, (self.n["Lockfile"]("second", "cargo"), self.n["Lockfile"]("safe", "npm")))
        self.assertEqual([x[2].opaque_id for x in result], ["second", "safe"])


if __name__ == "__main__":
    unittest.main()
