"""Tests must never write to the real out/ directory (audit log, register proposals, response files)."""
import os
import tempfile

os.environ.setdefault("OUT_DIR", tempfile.mkdtemp(prefix="agentmon_test_out_"))
