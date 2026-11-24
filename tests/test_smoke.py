import memwax
from memwax.cli import main


def test_version_string():
    assert memwax.__version__.count(".") == 2


def test_cli_runs_without_arguments(capsys):
    assert main([]) == 0
    assert "memwax" in capsys.readouterr().out
