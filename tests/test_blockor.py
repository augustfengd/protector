from challenge.blockor import block


def test_block_single_ip(monkeypatch):

    def mock_subprocess_run_iptables(*args, **_):

        action = args[0][1]

        class CompletedProcess:

            def __init__(self, returncode: int = 0):

                self.returncode = returncode

        if action == "-C":

            return CompletedProcess(returncode = 1)

        elif action == "-A":

            return CompletedProcess(returncode = 0)

    import subprocess

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run_iptables)

    scanners = {"8.8.8.8"}

    blocks = block(scanners=scanners)

    assert len(blocks) == 1


def test_block_many_ip(monkeypatch):

    def mock_subprocess_run_iptables(*args, **_):

        action = args[0][1]

        class CompletedProcess:

            def __init__(self, returncode: int = 0):

                self.returncode = returncode

        if action == "-C":

            return CompletedProcess(returncode = 1)

        elif action == "-A":

            return CompletedProcess(returncode = 0)

    import subprocess

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run_iptables)

    scanners = {"1.2.3.4", "8.8.8.8"}

    blocks = block(scanners=scanners)

    assert len(blocks) == 2


def test_block_single_ip_safelist(monkeypatch):

    def mock_subprocess_run_iptables(*args, **_):

        action = args[0][1]

        class CompletedProcess:

            def __init__(self, returncode: int = 0):

                self.returncode = returncode

        if action == "-C":

            return CompletedProcess(returncode = 1)

        elif action == "-A":

            return CompletedProcess(returncode = 0)

    import subprocess

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run_iptables)

    scanners = {"10.0.0.1"}

    blocks = block(scanners=scanners)

    assert len(blocks) == 0
