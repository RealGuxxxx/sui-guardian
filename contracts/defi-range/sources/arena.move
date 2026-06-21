module defi_range::arena {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::event;
    use sui::object::{Self, ID, UID};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    public struct LendingPool has key {
        id: UID,
        admin: address,
        vault: Balance<SUI>,
    }

    public struct AdminVault has key {
        id: UID,
        admin: address,
        vault: Balance<SUI>,
    }

    public struct OracleFeed has key {
        id: UID,
        admin: address,
        price: u64,
    }

    public struct PriceBank has key {
        id: UID,
        admin: address,
        oracle_id: ID,
        min_price_for_borrow: u64,
        vault: Balance<SUI>,
    }

    public struct ArenaCreated has copy, drop {
        admin: address,
        lending_pool_id: ID,
        admin_vault_id: ID,
        oracle_id: ID,
        price_bank_id: ID,
    }

    public struct DepositEvent has copy, drop {
        target: ID,
        sender: address,
        amount: u64,
        bucket: vector<u8>,
    }

    public struct OracleUpdated has copy, drop {
        oracle_id: ID,
        caller: address,
        old_price: u64,
        new_price: u64,
    }

    public struct AdminChanged has copy, drop {
        vault_id: ID,
        caller: address,
        old_admin: address,
        new_admin: address,
    }

    public struct Borrowed has copy, drop {
        bank_id: ID,
        borrower: address,
        amount: u64,
        oracle_price: u64,
    }

    public struct EmergencyWithdrawn has copy, drop {
        pool_id: ID,
        caller: address,
        recipient: address,
        amount: u64,
    }

    public struct AdminWithdrawn has copy, drop {
        vault_id: ID,
        caller: address,
        recipient: address,
        amount: u64,
    }

    const BUCKET_LENDING: vector<u8> = b"lending";
    const BUCKET_ADMIN: vector<u8> = b"admin_vault";
    const BUCKET_BANK: vector<u8> = b"price_bank";

    fun init(ctx: &mut TxContext) {
        let sender = tx_context::sender(ctx);
        let oracle = OracleFeed {
            id: object::new(ctx),
            admin: sender,
            price: 100,
        };
        let oracle_id = object::id(&oracle);

        let lending_pool = LendingPool {
            id: object::new(ctx),
            admin: sender,
            vault: balance::zero(),
        };
        let lending_pool_id = object::id(&lending_pool);

        let admin_vault = AdminVault {
            id: object::new(ctx),
            admin: sender,
            vault: balance::zero(),
        };
        let admin_vault_id = object::id(&admin_vault);

        let price_bank = PriceBank {
            id: object::new(ctx),
            admin: sender,
            oracle_id,
            min_price_for_borrow: 1_000,
            vault: balance::zero(),
        };
        let price_bank_id = object::id(&price_bank);

        event::emit(ArenaCreated {
            admin: sender,
            lending_pool_id,
            admin_vault_id,
            oracle_id,
            price_bank_id,
        });

        transfer::share_object(lending_pool);
        transfer::share_object(admin_vault);
        transfer::share_object(oracle);
        transfer::share_object(price_bank);
    }

    public entry fun seed_lending(pool: &mut LendingPool, payment: Coin<SUI>, ctx: &mut TxContext) {
        let amount = coin::value(&payment);
        balance::join(&mut pool.vault, coin::into_balance(payment));
        event::emit(DepositEvent { target: object::id(pool), sender: tx_context::sender(ctx), amount, bucket: BUCKET_LENDING });
    }

    public entry fun seed_admin_vault(vault: &mut AdminVault, payment: Coin<SUI>, ctx: &mut TxContext) {
        let amount = coin::value(&payment);
        balance::join(&mut vault.vault, coin::into_balance(payment));
        event::emit(DepositEvent { target: object::id(vault), sender: tx_context::sender(ctx), amount, bucket: BUCKET_ADMIN });
    }

    public entry fun seed_price_bank(bank: &mut PriceBank, payment: Coin<SUI>, ctx: &mut TxContext) {
        let amount = coin::value(&payment);
        balance::join(&mut bank.vault, coin::into_balance(payment));
        event::emit(DepositEvent { target: object::id(bank), sender: tx_context::sender(ctx), amount, bucket: BUCKET_BANK });
    }

    /// 漏洞 1：任何人都能直接抽干 lending pool。
    public entry fun emergency_withdraw_all(pool: &mut LendingPool, recipient: address, ctx: &mut TxContext) {
        let amount = balance::value(&pool.vault);
        let payout = balance::split(&mut pool.vault, amount);
        transfer::public_transfer(coin::from_balance(payout, ctx), recipient);
        event::emit(EmergencyWithdrawn { pool_id: object::id(pool), caller: tx_context::sender(ctx), recipient, amount });
    }

    /// 漏洞 2：任何人都能把 admin 改成自己。
    public entry fun change_admin_anyone(vault: &mut AdminVault, new_admin: address, ctx: &mut TxContext) {
        let old_admin = vault.admin;
        vault.admin = new_admin;
        event::emit(AdminChanged {
            vault_id: object::id(vault),
            caller: tx_context::sender(ctx),
            old_admin,
            new_admin,
        });
    }

    public entry fun admin_withdraw(vault: &mut AdminVault, recipient: address, amount: u64, ctx: &mut TxContext) {
        assert!(tx_context::sender(ctx) == vault.admin, 100);
        assert!(balance::value(&vault.vault) >= amount, 101);
        let payout = balance::split(&mut vault.vault, amount);
        transfer::public_transfer(coin::from_balance(payout, ctx), recipient);
        event::emit(AdminWithdrawn {
            vault_id: object::id(vault),
            caller: tx_context::sender(ctx),
            recipient,
            amount,
        });
    }

    /// 漏洞 3：任何人都能篡改预言机价格。
    public entry fun update_price_anyone(feed: &mut OracleFeed, new_price: u64, ctx: &mut TxContext) {
        let old_price = feed.price;
        feed.price = new_price;
        event::emit(OracleUpdated {
            oracle_id: object::id(feed),
            caller: tx_context::sender(ctx),
            old_price,
            new_price,
        });
    }

    /// 业务逻辑缺陷：只要预言机价格达到阈值，就能无抵押借出资金。
    public entry fun borrow_by_oracle(bank: &mut PriceBank, feed: &OracleFeed, recipient: address, amount: u64, ctx: &mut TxContext) {
        assert!(object::id(feed) == bank.oracle_id, 200);
        assert!(feed.price >= bank.min_price_for_borrow, 201);
        assert!(balance::value(&bank.vault) >= amount, 202);
        let payout = balance::split(&mut bank.vault, amount);
        transfer::public_transfer(coin::from_balance(payout, ctx), recipient);
        event::emit(Borrowed {
            bank_id: object::id(bank),
            borrower: tx_context::sender(ctx),
            amount,
            oracle_price: feed.price,
        });
    }

    public fun lending_vault(pool: &LendingPool): u64 { balance::value(&pool.vault) }
    public fun admin_vault_balance(vault: &AdminVault): u64 { balance::value(&vault.vault) }
    public fun oracle_price(feed: &OracleFeed): u64 { feed.price }
    public fun price_bank_vault(bank: &PriceBank): u64 { balance::value(&bank.vault) }
}
