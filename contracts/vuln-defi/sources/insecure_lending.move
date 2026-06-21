module vuln_defi::insecure_lending {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::event;
    use sui::object::{Self, ID, UID};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    public struct Pool has key {
        id: UID,
        admin: address,
        vault: Balance<SUI>,
    }

    public struct PoolCreated has copy, drop {
        pool_id: ID,
        admin: address,
    }

    public struct Deposit has copy, drop {
        pool_id: ID,
        sender: address,
        amount: u64,
    }

    public struct EmergencyWithdraw has copy, drop {
        pool_id: ID,
        caller: address,
        recipient: address,
        amount: u64,
    }

    fun init(ctx: &mut TxContext) {
        let pool = Pool {
            id: object::new(ctx),
            admin: tx_context::sender(ctx),
            vault: balance::zero(),
        };

        let pool_id = object::id(&pool);
        event::emit(PoolCreated {
            pool_id,
            admin: tx_context::sender(ctx),
        });

        transfer::share_object(pool);
    }

    public entry fun deposit(pool: &mut Pool, payment: Coin<SUI>, ctx: &mut TxContext) {
        let amount = coin::value(&payment);
        balance::join(&mut pool.vault, coin::into_balance(payment));

        event::emit(Deposit {
            pool_id: object::id(pool),
            sender: tx_context::sender(ctx),
            amount,
        });
    }

    /// 故意留下的严重漏洞：没有任何 admin 校验。
    /// 任意地址都可以把池子里的全部 SUI 转给自己。
    public entry fun emergency_withdraw_all(pool: &mut Pool, recipient: address, ctx: &mut TxContext) {
        let amount = balance::value(&pool.vault);
        let payout_balance = balance::split(&mut pool.vault, amount);
        let payout_coin = coin::from_balance(payout_balance, ctx);

        transfer::public_transfer(payout_coin, recipient);

        event::emit(EmergencyWithdraw {
            pool_id: object::id(pool),
            caller: tx_context::sender(ctx),
            recipient,
            amount,
        });
    }

    public fun pool_admin(pool: &Pool): address {
        pool.admin
    }

    public fun vault_balance(pool: &Pool): u64 {
        balance::value(&pool.vault)
    }
}
