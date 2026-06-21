#!/usr/bin/env python3
import argparse
import json
import re
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_DIR = PROJECT_ROOT / 'contracts' / 'defi-range'
CONFIG_PATH = PROJECT_ROOT / 'config' / 'generated-defi-range.yml'
STATE_PATH = PROJECT_ROOT / '.data' / 'generated-defi-range-state.json'
REPORT_PATH = PROJECT_ROOT / 'runbooks' / 'latest-defi-range.json'
LOG_PATH = PROJECT_ROOT / '.data' / 'generated-defi-range-monitor.log'
CLIENT_YAML = Path.home() / '.sui' / 'sui_config' / 'client.yaml'

MODULE = 'arena'
DEFAULT_ATTACKER_FUNDING = 100_000_000
SEED_AMOUNT = 300_000_000
SUCCESS_BORROW_RESERVE = 100_000_000


class CommandError(RuntimeError):
    pass


def print_step(message: str) -> None:
    print(f'\n=== {message} ===')
    sys.stdout.flush()


def run_cmd(args: List[str], cwd: Optional[Path] = None, check: bool = True) -> Tuple[int, str]:
    print('$ ' + ' '.join(args))
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
        raise CommandError(f"Command failed ({completed.returncode}): {' '.join(args)}")
    return completed.returncode, output


def extract_json_blob(text: str) -> Any:
    for index, char in enumerate(text):
        if char not in '{[':
            continue
        try:
            return json.loads(text[index:])
        except json.JSONDecodeError:
            continue
    raise ValueError(f'No JSON payload found in output:\n{text}')


def parse_active_env() -> str:
    content = CLIENT_YAML.read_text(encoding='utf-8')
    match = re.search(r'^active_env:\s*(.+)$', content, flags=re.MULTILINE)
    if not match:
        raise RuntimeError('Unable to determine active_env')
    return match.group(1).strip().strip('"')


def get_active_address() -> str:
    _, output = run_cmd(['sui', 'client', 'active-address'])
    matches = re.findall(r'0x[a-f0-9]{64}', output)
    if not matches:
        raise RuntimeError('Unable to determine active address')
    return matches[-1]


def list_addresses() -> List[str]:
    _, output = run_cmd(['sui', 'client', 'addresses'])
    return re.findall(r'0x[a-f0-9]{64}', output)


def switch_address(address: str) -> None:
    run_cmd(['sui', 'client', 'switch', '--address', address])


def get_gas_objects(address: str) -> List[Dict[str, Any]]:
    _, output = run_cmd(['sui', 'client', 'gas', address, '--json'])
    payload = extract_json_blob(output)
    if not isinstance(payload, list):
        raise RuntimeError('Unexpected gas output')
    return payload


def total_mist(coins: List[Dict[str, Any]]) -> int:
    return sum(int(item.get('mistBalance', 0)) for item in coins)


def select_gas_coin_id(coins: List[Dict[str, Any]], amount: int, gas_budget: int) -> str:
    required = amount + gas_budget
    for item in coins:
        if int(item.get('mistBalance', 0)) >= required:
            return item['gasCoinId']

    richest = max(coins, key=lambda item: int(item.get('mistBalance', 0)), default=None)
    if richest is None:
        raise RuntimeError('No gas coins available')
    return richest['gasCoinId']


def select_transfer_amount(coins: List[Dict[str, Any]], target_amount: int, gas_budget: int) -> int:
    richest_balance = max((int(item.get('mistBalance', 0)) for item in coins), default=0)
    safe_max = richest_balance - gas_budget
    if safe_max <= 0:
        raise RuntimeError('No gas coin can cover transfer gas budget')
    return min(target_amount, safe_max)


def select_success_borrow_amount(seed_amount: int, reserve: int = SUCCESS_BORROW_RESERVE) -> int:
    if seed_amount <= 1:
        raise RuntimeError('Seed amount must be greater than 1')

    safe_max = seed_amount - reserve if seed_amount > reserve else max(1, seed_amount // 2)
    return min(1_000_000_000, safe_max)


def select_admin_withdraw_amount(seed_amount: int) -> int:
    if seed_amount <= 0:
        raise RuntimeError('Seed amount must be positive')
    return min(1_000_000_000, seed_amount)


def ensure_attacker_gas(admin: str, attacker: str, min_mist: int) -> Optional[str]:
    attacker_coins = get_gas_objects(attacker)
    if total_mist(attacker_coins) >= min_mist:
        return None
    switch_address(admin)
    admin_gas = get_gas_objects(admin)
    gas_coin = select_gas_coin_id(admin_gas, min_mist, 10_000_000)
    _, output = run_cmd([
        'sui', 'client', 'transfer-sui',
        '--to', attacker,
        '--sui-coin-object-id', gas_coin,
        '--amount', str(min_mist),
        '--gas-budget', '10000000',
        '--json',
    ])
    payload = extract_json_blob(output)
    return payload.get('digest')


def publish_range() -> Dict[str, Any]:
    published_file = CONTRACT_DIR / 'Published.toml'
    original_published = published_file.read_text(encoding='utf-8') if published_file.exists() else None
    published_file.unlink(missing_ok=True)
    try:
        _, output = run_cmd([
            'sui', 'client', 'publish',
            '--gas-budget', '100000000',
            '--json',
            '.',
        ], cwd=CONTRACT_DIR)
    finally:
        if original_published is not None:
            published_file.write_text(original_published, encoding='utf-8')
        else:
            published_file.unlink(missing_ok=True)
    payload = extract_json_blob(output)
    package_id = None
    objects: Dict[str, str] = {}
    for change in payload.get('objectChanges', []):
        if change.get('type') == 'published':
            package_id = change.get('packageId')
        if change.get('type') == 'created':
            obj_type = change.get('objectType', '')
            if obj_type.endswith('::LendingPool'):
                objects['lending_pool'] = change['objectId']
            elif obj_type.endswith('::AdminVault'):
                objects['admin_vault'] = change['objectId']
            elif obj_type.endswith('::OracleFeed'):
                objects['oracle_feed'] = change['objectId']
            elif obj_type.endswith('::PriceBank'):
                objects['price_bank'] = change['objectId']
            elif obj_type == '0x2::package::UpgradeCap':
                objects['upgrade_cap'] = change['objectId']
    if not package_id or len(objects) < 4:
        raise RuntimeError('Failed to parse publish output for arena range')
    return {
        'digest': payload.get('digest'),
        'package_id': package_id,
        'objects': objects,
        'raw': payload,
    }


def create_self_coin(address: str, amount: int) -> Dict[str, Any]:
    gas_objects = get_gas_objects(address)
    transfer_amount = select_transfer_amount(gas_objects, amount, 10_000_000)
    gas_coin = select_gas_coin_id(gas_objects, transfer_amount, 10_000_000)
    _, output = run_cmd([
        'sui', 'client', 'transfer-sui',
        '--to', address,
        '--sui-coin-object-id', gas_coin,
        '--amount', str(transfer_amount),
        '--gas-budget', '10000000',
        '--json',
    ])
    payload = extract_json_blob(output)
    created_coin = None
    for change in payload.get('objectChanges', []):
        if change.get('type') == 'created' and change.get('objectType') == '0x2::coin::Coin<0x2::sui::SUI>':
            created_coin = change.get('objectId')
            break
    if not created_coin:
        raise RuntimeError('Failed to create seed coin')
    return {'digest': payload.get('digest'), 'coin_id': created_coin, 'amount': transfer_amount, 'raw': payload}


def call_json(args: List[str], check: bool = True) -> Dict[str, Any]:
    _, output = run_cmd(args + ['--json'], check=check)
    return extract_json_blob(output)


def seed_target(package_id: str, function_name: str, object_id: str, coin_id: str) -> Dict[str, Any]:
    payload = call_json([
        'sui', 'client', 'call',
        '--package', package_id,
        '--module', MODULE,
        '--function', function_name,
        '--args', object_id, coin_id,
        '--gas-budget', '10000000',
    ])
    return {'digest': payload.get('digest'), 'raw': payload}


def failed_probe(package_id: str, price_bank_id: str, oracle_id: str, recipient: str, amount: int) -> Dict[str, Any]:
    # keep check=False so failed on-chain execution can still proceed and contribute to failure bursts
    _, output = run_cmd([
        'sui', 'client', 'call',
        '--package', package_id,
        '--module', MODULE,
        '--function', 'borrow_by_oracle',
        '--args', price_bank_id, oracle_id, recipient, str(amount),
        '--gas-budget', '10000000',
        '--json',
    ], check=False)
    digest_match = re.search(r"transaction '([A-Za-z0-9]+)'", output)
    return {
        'digest': digest_match.group(1) if digest_match else None,
        'raw_output': output,
    }


def update_price(package_id: str, oracle_id: str, new_price: int) -> Dict[str, Any]:
    payload = call_json([
        'sui', 'client', 'call',
        '--package', package_id,
        '--module', MODULE,
        '--function', 'update_price_anyone',
        '--args', oracle_id, str(new_price),
        '--gas-budget', '10000000',
    ])
    return {'digest': payload.get('digest'), 'raw': payload}


def borrow_success(package_id: str, price_bank_id: str, oracle_id: str, recipient: str, amount: int) -> Dict[str, Any]:
    payload = call_json([
        'sui', 'client', 'call',
        '--package', package_id,
        '--module', MODULE,
        '--function', 'borrow_by_oracle',
        '--args', price_bank_id, oracle_id, recipient, str(amount),
        '--gas-budget', '10000000',
    ])
    return {'digest': payload.get('digest'), 'raw': payload}


def change_admin(package_id: str, admin_vault_id: str, new_admin: str) -> Dict[str, Any]:
    payload = call_json([
        'sui', 'client', 'call',
        '--package', package_id,
        '--module', MODULE,
        '--function', 'change_admin_anyone',
        '--args', admin_vault_id, new_admin,
        '--gas-budget', '10000000',
    ])
    return {'digest': payload.get('digest'), 'raw': payload}


def admin_withdraw(package_id: str, admin_vault_id: str, recipient: str, amount: int) -> Dict[str, Any]:
    payload = call_json([
        'sui', 'client', 'call',
        '--package', package_id,
        '--module', MODULE,
        '--function', 'admin_withdraw',
        '--args', admin_vault_id, recipient, str(amount),
        '--gas-budget', '10000000',
    ])
    return {'digest': payload.get('digest'), 'raw': payload}


def emergency_withdraw(package_id: str, lending_pool_id: str, recipient: str) -> Dict[str, Any]:
    payload = call_json([
        'sui', 'client', 'call',
        '--package', package_id,
        '--module', MODULE,
        '--function', 'emergency_withdraw_all',
        '--args', lending_pool_id, recipient,
        '--gas-budget', '10000000',
    ])
    return {'digest': payload.get('digest'), 'raw': payload}


def reset_state_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        'lastCheckpoint': 0,
        'packageVersions': {},
        'trackedObjectSnapshots': {},
        'priceReferenceProfiles': {},
        'objectBaselineProfiles': {},
        'flowHistory': {},
        'recentTransactionDigests': [],
        'recentAlerts': [],
        'scanHistory': [],
        'updatedAt': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')


def free_port(start_port: int = 3011) -> int:
    for port in range(start_port, start_port + 40):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(('127.0.0.1', port))
            except OSError:
                continue
            return port
    raise RuntimeError('No free port available')


def write_config(port: int, package_id: str, objects: Dict[str, str], admin: str) -> None:
    content = f'''network:
  name: testnet
  graphqlEndpoint: https://graphql.testnet.sui.io/graphql
  pollIntervalMs: 5000
  bootstrapLookbackCheckpoints: 0
  checkpointOverlap: 1
  maxCheckpointsPerTick: 45
  maxTransactionsPerPage: 50

storage:
  stateFile: {STATE_PATH.relative_to(PROJECT_ROOT)}
  maxAlerts: 1000

server:
  host: 0.0.0.0
  port: {port}

alerts:
  console: true
  webhookUrl: ""

aiRules:
  enabled: false
  generatedDir: .data/generated
  reloadIntervalMs: 60000

projects:
  - id: defi-range-lab
    name: Sui DeFi 多漏洞靶场
    packages:
      - label: defi-range-arena
        address: "{package_id}"
        allowedUpgradeSenders:
          - "{admin}"
    protectedAddresses:
      - label: lending-pool-vault
        address: "{objects['lending_pool']}"
        outflowThresholds:
          "0x2::sui::SUI": "100000000"
        allowedSenders:
          - "{admin}"
      - label: admin-vault
        address: "{objects['admin_vault']}"
        outflowThresholds:
          "0x2::sui::SUI": "100000000"
        allowedSenders:
          - "{admin}"
      - label: price-bank-vault
        address: "{objects['price_bank']}"
        outflowThresholds:
          "0x2::sui::SUI": "100000000"
        allowedSenders:
          - "{admin}"
    functionGuards:
      - label: lending-emergency-withdraw
        package: "{package_id}"
        module: {MODULE}
        function: emergency_withdraw_all
        allowedSenders:
          - "{admin}"
        severity: critical
      - label: admin-takeover
        package: "{package_id}"
        module: {MODULE}
        function: change_admin_anyone
        allowedSenders:
          - "{admin}"
        severity: high
      - label: admin-withdraw
        package: "{package_id}"
        module: {MODULE}
        function: admin_withdraw
        allowedSenders:
          - "{admin}"
        severity: critical
      - label: oracle-update
        package: "{package_id}"
        module: {MODULE}
        function: update_price_anyone
        allowedSenders:
          - "{admin}"
        severity: high
    trafficSpikes:
      - label: arena-hot-path
        package: "{package_id}"
        windowSeconds: 120
        txCountThreshold: 4
        uniqueSenderThreshold: 1
        severity: low
        cooldownSeconds: 120
    failureSpikes:
      - label: arena-probe-burst
        package: "{package_id}"
        windowSeconds: 120
        failedTxThreshold: 2
        severity: medium
        cooldownSeconds: 120
    trackedObjects:
      - label: lending-pool
        address: "{objects['lending_pool']}"
        watchFields: [admin, vault]
        criticalFields: [admin]
        numericDecreaseThresholds:
          vault: "100000000"
        severity: critical
      - label: admin-vault
        address: "{objects['admin_vault']}"
        watchFields: [admin, vault]
        criticalFields: [admin]
        numericDecreaseThresholds:
          vault: "100000000"
        severity: critical
      - label: oracle-feed
        address: "{objects['oracle_feed']}"
        watchFields: [admin, price]
        criticalFields: [price]
        severity: high
      - label: price-bank
        address: "{objects['price_bank']}"
        watchFields: [admin, oracle_id, min_price_for_borrow, vault]
        numericDecreaseThresholds:
          vault: "100000000"
        severity: critical
    suspiciousTargets: []
    behaviorRules:
      enabled: true
      minRepeatedCalls: 2
      minProtectedOutflow: "100000000"
      priceDeviationThresholdBps: 1500
    priceModels:
      - label: oracle-feed-price
        trackedObjectLabel: oracle-feed
        observedFieldPath: price
        referenceMode: rolling_median
        deviationThresholdBps: 1500
    objectBaselines:
      - label: lending-pool-admin
        trackedObjectLabel: lending-pool
        fields:
          - path: admin
            kind: permission
            allowedSenders:
              - "{admin}"
          - path: vault
            kind: inventory
            maxAbsoluteDecrease: "100000000"
      - label: admin-vault-admin
        trackedObjectLabel: admin-vault
        fields:
          - path: admin
            kind: permission
            allowedSenders:
              - "{admin}"
          - path: vault
            kind: inventory
            maxAbsoluteDecrease: "100000000"
      - label: oracle-feed-price
        trackedObjectLabel: oracle-feed
        fields:
          - path: price
            kind: price
            allowedSenders:
              - "{admin}"
            maxDeltaBps: 1500
      - label: price-bank-vault
        trackedObjectLabel: price-bank
        fields:
          - path: vault
            kind: inventory
            maxAbsoluteDecrease: "100000000"
    flowTracking:
      enabled: true
      minProtectedOutflow: "100000000"
      attackerGainThreshold: "100000000"
      shortWindowTxCount: 2
    suppression:
      enabled: true
      duplicateWindowSeconds: 600
      weakSignalScoreThreshold: 35
      maintenanceWindows: []
'''
    CONFIG_PATH.write_text(content, encoding='utf-8')


def wait_for_health(port: int, timeout: int = 60) -> None:
    deadline = time.time() + timeout
    url = f'http://127.0.0.1:{port}/api/health'
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                if response.status == 200:
                    return
        except Exception:
            time.sleep(1)
    raise RuntimeError(f'Monitor did not become healthy on port {port}')


def fetch_json(url: str) -> Any:
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.loads(response.read().decode('utf-8'))


def start_monitor(port: int) -> subprocess.Popen:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    log_handle = LOG_PATH.open('w', encoding='utf-8')
    process = subprocess.Popen(
        ['npm', 'start', '--', '--config', str(CONFIG_PATH.relative_to(PROJECT_ROOT))],
        cwd=str(PROJECT_ROOT),
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        text=True,
    )
    wait_for_health(port)
    return process


def wait_for_alerts(port: int, expected_rules: List[str], timeout: int = 180) -> List[Dict[str, Any]]:
    deadline = time.time() + timeout
    url = f'http://127.0.0.1:{port}/api/alerts?limit=1000'
    wanted = set(expected_rules)
    while time.time() < deadline:
        alerts = fetch_json(url)
        got = {alert.get('ruleId') for alert in alerts}
        if wanted.issubset(got):
            return alerts
        time.sleep(3)
    raise RuntimeError(f'Alerts not fully observed in time. Missing: {sorted(wanted - got)}')


def stop_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def write_report(report: Dict[str, Any]) -> None:
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')


def main() -> int:
    parser = argparse.ArgumentParser(description='Run a multi-vulnerability Sui DeFi range with monitoring')
    parser.add_argument('--stop-monitor-at-end', action='store_true')
    parser.add_argument('--alert-timeout', type=int, default=180)
    args = parser.parse_args()

    original_address = None
    monitor_process: Optional[subprocess.Popen] = None
    try:
        print_step('Checking testnet environment')
        if parse_active_env() != 'testnet':
            raise RuntimeError('Active Sui env must be testnet')
        original_address = get_active_address()
        addresses = list_addresses()
        admin = original_address
        attacker = next(address for address in addresses if address != admin)
        print(f'Admin address:    {admin}')
        print(f'Attacker address: {attacker}')

        print_step('Funding attacker if needed')
        funding_digest = ensure_attacker_gas(admin, attacker, DEFAULT_ATTACKER_FUNDING)

        print_step('Publishing multi-vulnerability DeFi range')
        switch_address(admin)
        publish_result = publish_range()

        print_step('Creating seed coins')
        lending_coin = create_self_coin(admin, SEED_AMOUNT)
        admin_vault_coin = create_self_coin(admin, SEED_AMOUNT)
        price_bank_coin = create_self_coin(admin, SEED_AMOUNT)

        print_step('Seeding all vulnerable objects')
        objects = publish_result['objects']
        seed_lending = seed_target(publish_result['package_id'], 'seed_lending', objects['lending_pool'], lending_coin['coin_id'])
        seed_admin_vault = seed_target(publish_result['package_id'], 'seed_admin_vault', objects['admin_vault'], admin_vault_coin['coin_id'])
        seed_price_bank = seed_target(publish_result['package_id'], 'seed_price_bank', objects['price_bank'], price_bank_coin['coin_id'])

        print_step('Preparing monitor config for situational awareness dashboard')
        port = free_port(3011)
        reset_state_file(STATE_PATH)
        write_config(port, publish_result['package_id'], objects, admin)
        run_cmd(['npm', 'run', 'build'], cwd=PROJECT_ROOT)
        monitor_process = start_monitor(port)
        monitor_url = f'http://127.0.0.1:{port}/'
        print(f'Dashboard URL: {monitor_url}')

        print_step('Launching staged attack sequence')
        switch_address(attacker)
        failed_borrows = []
        for _ in range(2):
            payload = failed_probe(publish_result['package_id'], objects['price_bank'], objects['oracle_feed'], attacker, 400_000_000)
            failed_borrows.append(payload)
        oracle_attack = update_price(publish_result['package_id'], objects['oracle_feed'], 5000)
        success_borrow_amount = select_success_borrow_amount(price_bank_coin['amount'])
        price_bank_drain = borrow_success(
            publish_result['package_id'],
            objects['price_bank'],
            objects['oracle_feed'],
            attacker,
            success_borrow_amount,
        )
        admin_takeover = change_admin(publish_result['package_id'], objects['admin_vault'], attacker)
        admin_withdraw_amount = select_admin_withdraw_amount(admin_vault_coin['amount'])
        admin_drain = admin_withdraw(
            publish_result['package_id'],
            objects['admin_vault'],
            attacker,
            admin_withdraw_amount,
        )
        lending_drain = emergency_withdraw(publish_result['package_id'], objects['lending_pool'], attacker)

        print_step('Waiting for alert set and asset snapshots')
        expected_rules = [
            'function-guard:oracle-update',
            'function-guard:admin-takeover',
            'function-guard:admin-withdraw',
            'function-guard:lending-emergency-withdraw',
            'failure-spike:arena-probe-burst',
            f'tracked-object-drop:{objects["price_bank"]}:vault',
            f'tracked-object-critical:{objects["oracle_feed"]}:price',
            f'tracked-object-critical:{objects["admin_vault"]}:admin',
            f'tracked-object-drop:{objects["admin_vault"]}:vault',
            f'tracked-object-drop:{objects["lending_pool"]}:vault',
        ]
        alerts = wait_for_alerts(port, expected_rules, timeout=args.alert_timeout)
        metrics = fetch_json(f'http://127.0.0.1:{port}/api/metrics')
        assets = fetch_json(f'http://127.0.0.1:{port}/api/assets')
        scans = fetch_json(f'http://127.0.0.1:{port}/api/scans?limit=10')

        report = {
            'executed_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'network': 'testnet',
            'admin_address': admin,
            'attacker_address': attacker,
            'attacker_funding_digest': funding_digest,
            'publish': {
                'digest': publish_result['digest'],
                'package_id': publish_result['package_id'],
                'objects': objects,
            },
            'seed': {
                'lending': seed_lending['digest'],
                'admin_vault': seed_admin_vault['digest'],
                'price_bank': seed_price_bank['digest'],
            },
            'attacks': {
                'failed_borrows': [payload.get('digest') for payload in failed_borrows if isinstance(payload, dict)],
                'oracle_update': oracle_attack['digest'],
                'price_bank_drain': price_bank_drain['digest'],
                'price_bank_drain_amount': success_borrow_amount,
                'admin_takeover': admin_takeover['digest'],
                'admin_drain': admin_drain['digest'],
                'admin_drain_amount': admin_withdraw_amount,
                'lending_drain': lending_drain['digest'],
            },
            'monitor': {
                'url': monitor_url,
                'port': port,
                'config_path': str(CONFIG_PATH),
                'state_path': str(STATE_PATH),
                'log_path': str(LOG_PATH),
                'alerts': alerts,
                'metrics': metrics,
                'assets': assets,
                'recent_scans': scans,
            },
        }
        write_report(report)

        print_step('Range experiment complete')
        print(json.dumps({
            'dashboard': monitor_url,
            'package_id': publish_result['package_id'],
            'lending_pool': objects['lending_pool'],
            'admin_vault': objects['admin_vault'],
            'oracle_feed': objects['oracle_feed'],
            'price_bank': objects['price_bank'],
            'report_path': str(REPORT_PATH),
            'alert_count': len(alerts),
        }, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1
    finally:
        if monitor_process is not None and args.stop_monitor_at_end:
            stop_process(monitor_process)
        if original_address:
            try:
                switch_address(original_address)
            except Exception:
                pass


if __name__ == '__main__':
    sys.exit(main())
