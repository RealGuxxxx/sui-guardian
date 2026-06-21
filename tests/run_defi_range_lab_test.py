from pathlib import Path
import importlib.util
import yaml


def load_lab_module():
    module_path = Path(__file__).resolve().parents[1] / 'scripts' / 'run_defi_range_lab.py'
    spec = importlib.util.spec_from_file_location('run_defi_range_lab', module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_select_gas_coin_prefers_sufficient_balance():
    module = load_lab_module()

    coin_id = module.select_gas_coin_id(
        [
            {'gasCoinId': 'small', 'mistBalance': 59_381_264},
            {'gasCoinId': 'enough', 'mistBalance': 474_526_480},
        ],
        amount=300_000_000,
        gas_budget=10_000_000,
    )

    assert coin_id == 'enough'


def test_select_success_borrow_amount_stays_within_seeded_vault():
    module = load_lab_module()

    amount = module.select_success_borrow_amount(300_000_000)

    assert amount == 200_000_000
    assert amount < 300_000_000


def test_select_transfer_amount_falls_back_to_safe_max_when_no_coin_covers_target():
    module = load_lab_module()

    amount = module.select_transfer_amount(
        [
            {'gasCoinId': 'a', 'mistBalance': 256_357_452},
            {'gasCoinId': 'b', 'mistBalance': 300_000_000},
            {'gasCoinId': 'c', 'mistBalance': 200_000_000},
        ],
        target_amount=300_000_000,
        gas_budget=10_000_000,
    )

    assert amount == 290_000_000


def test_select_admin_withdraw_amount_uses_seeded_vault_cap():
    module = load_lab_module()

    amount = module.select_admin_withdraw_amount(290_000_000)

    assert amount == 290_000_000


def test_write_config_includes_overflow_readiness_blocks():
    module = load_lab_module()
    original_config_path = module.CONFIG_PATH
    original_state_path = module.STATE_PATH
    module.CONFIG_PATH = module.PROJECT_ROOT / '.data' / 'test-generated-defi-range.yml'
    module.STATE_PATH = module.PROJECT_ROOT / '.data' / 'test-generated-defi-range-state.json'
    try:
        package_id = '0x' + '1' * 64
        admin = '0x' + 'a' * 64
        objects = {
            'lending_pool': '0x' + '2' * 64,
            'admin_vault': '0x' + '3' * 64,
            'oracle_feed': '0x' + '4' * 64,
            'price_bank': '0x' + '5' * 64,
        }

        module.write_config(3011, package_id, objects, admin)

        parsed = yaml.safe_load(module.CONFIG_PATH.read_text(encoding='utf-8'))
        project = parsed['projects'][0]
        assert project['behaviorRules']['enabled'] is True
        assert len(project['protectedAddresses']) == 3
        assert project['protectedAddresses'][0]['address'] == objects['lending_pool']
        assert project['protectedAddresses'][1]['address'] == objects['admin_vault']
        assert project['protectedAddresses'][2]['address'] == objects['price_bank']
        assert len(project['trackedObjects']) == 4
        assert len(project['objectBaselines']) == 4
        assert project['priceModels'][0]['trackedObjectLabel'] == 'oracle-feed'
        assert project['flowTracking']['enabled'] is True
        assert project['suppression']['enabled'] is True
    finally:
        module.CONFIG_PATH = original_config_path
        module.STATE_PATH = original_state_path
