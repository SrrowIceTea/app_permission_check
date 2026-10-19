"""Compile the real session entry; mocks are not device evidence."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch
from mobile.lab.core_observer import compile_session

class EntryTests(TestCase):
    def test_exported_hooks_are_invoked_in_single_bridge_session(self):
        entries=[]
        def build(path, **kwargs):
            entries.append(Path(path).read_text(encoding="utf-8"))
            return "unit bundle"
        with TemporaryDirectory() as temp, patch("mobile.lab.core_observer.frida.Compiler") as compiler:
            compiler.return_value.build.side_effect=build
            compile_session(Path(temp))
        entry=entries[0]
        for index,name in enumerate(("hook_privacy", "hook_consent", "hook_egress_tp")):
            self.assertIn("import { main as hook%d }" % index,entry)
            self.assertIn("hook%d();" % index,entry)
        self.assertIn("Java.perform(",entry)

if __name__=="__main__":main()
