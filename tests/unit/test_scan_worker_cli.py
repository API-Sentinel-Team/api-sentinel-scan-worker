from __future__ import annotations

from sentinel_worker.modules.test_executor.scan_worker import build_arg_parser


def test_scan_worker_cli_defaults(monkeypatch):
    monkeypatch.delenv("API_SENTINEL_ACCOUNT_ID", raising=False)
    monkeypatch.delenv("API_SENTINEL_WORKER_ID", raising=False)
    monkeypatch.delenv("PENTEST_SCAN_WORKER_POLL_INTERVAL", raising=False)
    monkeypatch.delenv("PENTEST_SCAN_WORKER_MAX_RUNS", raising=False)

    args = build_arg_parser().parse_args([])
    assert args.account_id is None
    assert args.worker_id is None
    assert args.poll_interval == 2.0
    assert args.max_runs is None


def test_scan_worker_cli_env_and_flags(monkeypatch):
    monkeypatch.setenv("API_SENTINEL_ACCOUNT_ID", "42")
    monkeypatch.setenv("API_SENTINEL_WORKER_ID", "worker-a")
    monkeypatch.setenv("PENTEST_SCAN_WORKER_POLL_INTERVAL", "1.5")
    monkeypatch.setenv("PENTEST_SCAN_WORKER_MAX_RUNS", "3")

    parser = build_arg_parser()
    env_args = parser.parse_args([])
    assert env_args.account_id == 42
    assert env_args.worker_id == "worker-a"
    assert env_args.poll_interval == 1.5
    assert env_args.max_runs == 3

    flag_args = parser.parse_args(
        ["--account-id", "7", "--worker-id", "worker-b", "--poll-interval", "0.25", "--max-runs", "1"]
    )
    assert flag_args.account_id == 7
    assert flag_args.worker_id == "worker-b"
    assert flag_args.poll_interval == 0.25
    assert flag_args.max_runs == 1
