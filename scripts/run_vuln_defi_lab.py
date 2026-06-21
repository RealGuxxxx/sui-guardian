#!/usr/bin/env python3
import argparse
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_DIR = PROJECT_ROOT / 'contracts' / 'vuln-defi'
GENERATED_CONFIG_PATH = PROJECT_ROOT / 'config' / 'generated-vuln-defi-lab.yml'
GENERATED_STATE_PATH = PROJECT_ROOT / '.data' / 'generated-vuln-defi-lab-state.json'
GENERATED_REPORT_PATH = PROJECT_ROOT / 'runbooks' / 'latest-vuln-defi-lab.json'
MONITOR_LOG_PATH = PROJECT_ROOT / '.data' / 'generated-vuln-defi-lab-monitor.log'
SUI_CLIENT_YAML = Path.home() / '.sui' / 'sui_config' / 'client.yaml'

PACKAGE_NAME = 'insecure_lending'
MODULE_NAME = 'insecure_lending'
FUNCTION_NAME = 'emergency_withdraw_all'
DEFAULT_ATTACKER_FUNDING_MIST = 300_000_000
DEFAULT_DEPOSIT_MIST = 1_000_000_000


class CommandError(RuntimeError):
    pass


def print_step(message: str) -> None:
    print(f'\n=== {message} ===')
    sys.stdout.flush()


def run_cmd(args: List[str], cwd: Optional[Path] = None, check: bool = True) -> str:
    printable = ' '.join(args)
    print(f'$ {printable}')
    completed = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    output = completed.stdout or ''
    if output.strip():
        print(output.rstrip())
    if check and completed.returncode != 0:
        raise CommandError(f'Command failed ({completed.returncode}): {printable}')
    return output


def extract_json_blob(text: str) -> Any:
    candidates = [index for index, char in enumerate(text) if char in '{[']
    for index in candidates:
        snippet = text[index:]
        try:
            return json.loads(snippet)
        except json.JSONDecodeError:
            continue
    raise ValueError(f'No JSON payload found in output:\n{text}')


def parse_active_env() -> str:
    content = SUI_CLIENT_YAML.read_text(encoding='utf-8')
    match = re.search(r'^active_env:\s*(.+)$', content, flags=re.MULTILINE)
    if not match:
        raise RuntimeError('Unable to determine active_env from ~/.sui/sui_config/client.yaml')
    return match.group(1).strip().strip('"')


def get_active_address() -> str:
    output = run_cmd(['sui', 'client', 'active-address'])
    matches = re.findall(r'0x[a-f0-9]{64}', output)
    if not matches:
        raise RuntimeError('Unable to determine active address')
    return matches[-1]


def list_known_addresses() -> List[Tuple[str, str]]:
    output = run_cmd(['sui', 'client', 'addresses'])
    pairs = re.findall(r'│\s*([^│]+?)\s*│\s*(0x[a-f0-9]{64})\s*│', output)
    results: List[Tuple[str, str]] = []
    for alias, address in pairs:
        cleaned_alias = alias.strip()
        if cleaned_alias == 'alias':
            continue
        results.append((cleaned_alias, address))
    if not results:
        raise RuntimeError('Unable to parse addresses from `sui client addresses`')
    return results


def switch_address(address_or_alias: str) -> None:
    run_cmd(['sui', 'client', 'switch', '--address', address_or_alias])


def get_gas_objects(address_or_alias: str) -> List[Dict[str, Any]]:
    output = run_cmd(['sui', 'client', 'gas', address_or_alias, '--json'])
    payload = extract_json_blob(output)
    if not isinstance(payload, list):
        raise RuntimeError('Unexpected gas payload shape')
    return payload


def total_mist(coins: List[Dict[str, Any]]) -> int:
    return sum(int(item.get('mistBalance', 0)) for item in coins)


def ensure_attacker_has_gas(admin_address: str, attacker_address: str, minimum_mist: int) -> Optional[str]:
    attacker_coins = get_gas_objects(attacker_address)
    if total_mist(attacker_coins) >= minimum_mist:
        print(f'Attacker already has enough gas: {total_mist(attacker_coins)} MIST')
        return None

    print(f'Attacker gas is low; funding attacker with {minimum_mist} MIST from admin')
    switch_address(admin_address)
    admin_gas = get_gas_objects(admin_address)
    if not admin_gas:
        raise RuntimeError('Admin has no gas coins available')
    gas_coin = admin_gas[0]['gasCoinId']
    output = run_cmd([
        'sui', 'client', 'transfer-sui',
        '--to', attacker_address,
        '--sui-coin-object-id', gas_coin,
        '--amount', str(minimum_mist),
        '--gas-budget', '10000000',
        '--json',
    ])
    payload = extract_json_blob(output)
    return payload.get('digest')


def publish_contract() -> Dict[str, Any]:
    output = run_cmd(['sui', 'client', 'publish', '--gas-budget', '100000000', '--json', '.'], cwd=CONTRACT_DIR)
    payload = extract_json_blob(output)
    object_changes = payload.get('objectChanges', [])
    package_id = None
    pool_id = None
    upgrade_cap = None
    for change in object_changes:
        if change.get('type') == 'published':
            package_id = change.get('packageId')
        if change.get('type') == 'created' and change.get('objectType', '').endswith(f'::{MODULE_NAME}::Pool'):
            pool_id = change.get('objectId')
        if change.get('type') == 'created' and change.get('objectType') == '0x2::package::UpgradeCap':
            upgrade_cap = change.get('objectId')
    if not package_id or not pool_id:
        raise RuntimeError('Failed to parse package or pool object from publish output')
    return {
        'digest': payload.get('digest'),
        'package_id': package_id,
        'pool_id': pool_id,
        'upgrade_cap_id': upgrade_cap,
        'raw': payload,
    }


def create_coin_for_deposit(admin_address: str, deposit_mist: int) -> Dict[str, Any]:
    admin_gas = get_gas_objects(admin_address)
    if not admin_gas:
        raise RuntimeError('Admin has no gas coins to create a deposit coin')
    gas_coin = admin_gas[0]['gasCoinId']
    output = run_cmd([
        'sui', 'client', 'transfer-sui',
        '--to', admin_address,
        '--sui-coin-object-id', gas_coin,
        '--amount', str(deposit_mist),
        '--gas-budget', '10000000',
        '--json',
    ])
    payload = extract_json_blob(output)
    coin_object_id = None
    for change in payload.get('objectChanges', []):
        if change.get('type') == 'created' and change.get('objectType') == '0x2::coin::Coin<0x2::sui::SUI>':
            coin_object_id = change.get('objectId')
            break
    if not coin_object_id:
        raise RuntimeError('Failed to create a dedicated deposit coin')
    return {
        'digest': payload.get('digest'),
        'coin_object_id': coin_object_id,
        'raw': payload,
    }


def deposit_into_pool(package_id: str, pool_id: str, coin_id: str) -> Dict[str, Any]:
    output = run_cmd([
        'sui', 'client', 'call',
        '--package', package_id,
        '--module', MODULE_NAME,
        '--function', 'deposit',
        '--args', pool_id, coin_id,
        '--gas-budget', '10000000',
        '--json',
    ])
    payload = extract_json_blob(output)
    return {
        'digest': payload.get('digest'),
        'raw': payload,
    }


def attack_pool(package_id: str, pool_id: str, attacker_address: str) -> Dict[str, Any]:
    output = run_cmd([
        'sui', 'client', 'call',
        '--package', package_id,
        '--module', MODULE_NAME,
        '--function', FUNCTION_NAME,
        '--args', pool_id, attacker_address,
        '--gas-budget', '10000000',
        '--json',
    ])
    payload = extract_json_blob(output)
    return {
        'digest': payload.get('digest'),
        'raw': payload,
    }


def find_free_port(start_port: int = 3010) -> int:
    for port in range(start_port, start_port + 50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(('127.0.0.1', port))
            except OSError:
                continue
            return port
    raise RuntimeError('Unable to find a free local port for the monitor server')


def reset_state_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        'lastCheckpoint': 0,
        'packageVersions': {},
        'recentTransactionDigests': [],
        'recentAlerts': [],
        'scanHistory': [],
        'updatedAt': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')


def write_monitor_config(path: Path, state_path: Path, port: int, package_id: str, admin_address: str) -> None:
    content = f'''network:
  name: testnet
  graphqlEndpoint: https://graphql.testnet.sui.io/graphql
  pollIntervalMs: 5000
  bootstrapLookbackCheckpoints: 80
  checkpointOverlap: 5
  maxCheckpointsPerTick: 10
  maxTransactionsPerPage: 50

storage:
  stateFile: {state_path.relative_to(PROJECT_ROOT)}
  maxAlerts: 200

server:
  host: 0.0.0.0
  port: {port}

alerts:
  console: true
  webhookUrl: ""

projects:
  - id: generated-vuln-defi-lab
    name: 自动化漏洞 DeFi 实验室
    packages:
      - label: insecure-lending
        address: "{package_id}"
        allowedUpgradeSenders:
          - "{admin_address}"
    protectedAddresses: []
    functionGuards:
      - label: emergency-withdraw-all
        package: "{package_id}"
        module: {MODULE_NAME}
        function: {FUNCTION_NAME}
        allowedSenders:
          - "{admin_address}"
        severity: critical
    trafficSpikes: []
    failureSpikes: []
'''
    path.write_text(content, encoding='utf-8')


def start_monitor(config_path: Path, port: int) -> Tuple[subprocess.Popen, Path]:
    MONITOR_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    log_handle = MONITOR_LOG_PATH.open('w', encoding='utf-8')
    process = subprocess.Popen(
        ['npm', 'start', '--', '--config', str(config_path.relative_to(PROJECT_ROOT))],
        cwd=str(PROJECT_ROOT),
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        text=True,
    )
    wait_for_health(port, timeout_seconds=60)
    return process, MONITOR_LOG_PATH


def wait_for_health(port: int, timeout_seconds: int) -> None:
    deadline = time.time() + timeout_seconds
    url = f'http://127.0.0.1:{port}/api/health'
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                if response.status == 200:
                    return
        except Exception:
            time.sleep(1)
    raise RuntimeError(f'Monitor server did not become healthy on port {port} within {timeout_seconds}s')


def fetch_json(url: str) -> Any:
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.loads(response.read().decode('utf-8'))


def wait_for_alert(port: int, attack_digest: str, timeout_seconds: int) -> Dict[str, Any]:
    deadline = time.time() + timeout_seconds
    alerts_url = f'http://127.0.0.1:{port}/api/alerts?limit=50'
    while time.time() < deadline:
        alerts = fetch_json(alerts_url)
        for alert in alerts:
            details = alert.get('details', {})
            if details.get('digest') == attack_digest:
                return alert
        time.sleep(2)
    raise RuntimeError(f'Alert for attack digest {attack_digest} was not observed within {timeout_seconds}s')


def stop_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def write_report(path: Path, report: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')


def main() -> int:
    parser = argparse.ArgumentParser(description='Run an end-to-end Sui testnet vulnerable DeFi monitor demo')
    parser.add_argument('--admin', help='Admin address or alias; defaults to current active address')
    parser.add_argument('--attacker', help='Attacker address or alias; defaults to the first other address in keystore')
    parser.add_argument('--attacker-min-mist', type=int, default=DEFAULT_ATTACKER_FUNDING_MIST)
    parser.add_argument('--deposit-mist', type=int, default=DEFAULT_DEPOSIT_MIST)
    parser.add_argument('--alert-timeout', type=int, default=120)
    args = parser.parse_args()

    original_active_address = None
    monitor_process: Optional[subprocess.Popen] = None
    try:
        print_step('Checking Sui environment')
        active_env = parse_active_env()
        if active_env != 'testnet':
            raise RuntimeError(f'Active env is {active_env}, expected testnet')
        original_active_address = get_active_address()
        known_addresses = list_known_addresses()
        admin_address = args.admin or original_active_address
        if args.attacker:
            attacker_address = args.attacker
        else:
            attacker_address = next(address for _, address in known_addresses if address != admin_address)

        print(f'Admin address:    {admin_address}')
        print(f'Attacker address: {attacker_address}')

        print_step('Ensuring attacker gas')
        attacker_funding_digest = ensure_attacker_has_gas(admin_address, attacker_address, args.attacker_min_mist)

        print_step('Publishing vulnerable DeFi contract')
        switch_address(admin_address)
        publish_result = publish_contract()
        package_id = publish_result['package_id']
        pool_id = publish_result['pool_id']

        print_step('Creating a dedicated deposit coin')
        deposit_coin = create_coin_for_deposit(admin_address, args.deposit_mist)

        print_step('Seeding the pool')
        deposit_result = deposit_into_pool(package_id, pool_id, deposit_coin['coin_object_id'])

        print_step('Preparing generated monitor config')
        port = find_free_port(3010)
        reset_state_file(GENERATED_STATE_PATH)
        write_monitor_config(GENERATED_CONFIG_PATH, GENERATED_STATE_PATH, port, package_id, admin_address)

        print_step('Building and starting monitor')
        run_cmd(['npm', 'run', 'build'], cwd=PROJECT_ROOT)
        monitor_process, log_path = start_monitor(GENERATED_CONFIG_PATH, port)
        monitor_url = f'http://127.0.0.1:{port}/'
        print(f'Monitor dashboard: {monitor_url}')

        print_step('Launching attack from non-admin address')
        switch_address(attacker_address)
        attack_result = attack_pool(package_id, pool_id, attacker_address)
        attack_digest = attack_result['digest']

        print_step('Waiting for alert confirmation')
        alert = wait_for_alert(port, attack_digest, args.alert_timeout)
        metrics = fetch_json(f'http://127.0.0.1:{port}/api/metrics')
        scans = fetch_json(f'http://127.0.0.1:{port}/api/scans?limit=5')

        print_step('Collecting final balances')
        admin_gas = get_gas_objects(admin_address)
        attacker_gas = get_gas_objects(attacker_address)

        report = {
            'executed_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'network': 'testnet',
            'admin_address': admin_address,
            'attacker_address': attacker_address,
            'attacker_funding_digest': attacker_funding_digest,
            'publish': {
                'digest': publish_result['digest'],
                'package_id': package_id,
                'pool_id': pool_id,
                'upgrade_cap_id': publish_result['upgrade_cap_id'],
            },
            'deposit': {
                'digest': deposit_result['digest'],
                'coin_object_id': deposit_coin['coin_object_id'],
                'amount_mist': args.deposit_mist,
            },
            'attack': {
                'digest': attack_digest,
            },
            'monitor': {
                'config_path': str(GENERATED_CONFIG_PATH),
                'state_path': str(GENERATED_STATE_PATH),
                'log_path': str(log_path),
                'url': monitor_url,
                'port': port,
                'alert': alert,
                'metrics': metrics,
                'recent_scans': scans,
            },
            'balances': {
                'admin_gas': admin_gas,
                'attacker_gas': attacker_gas,
            },
        }
        write_report(GENERATED_REPORT_PATH, report)

        print_step('Experiment complete')
        print(json.dumps({
            'package_id': package_id,
            'pool_id': pool_id,
            'publish_digest': publish_result['digest'],
            'deposit_digest': deposit_result['digest'],
            'attack_digest': attack_digest,
            'monitor_url': monitor_url,
            'alert_rule': alert.get('ruleName'),
            'alert_severity': alert.get('severity'),
            'report_path': str(GENERATED_REPORT_PATH),
        }, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1
    finally:
        if monitor_process is not None:
            stop_process(monitor_process)
        if original_active_address:
            try:
                switch_address(original_active_address)
            except Exception:
                pass


if __name__ == '__main__':
    sys.exit(main())
