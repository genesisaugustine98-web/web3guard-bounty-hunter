// SPDX-License-Identifier: MIT
// Move test contract (Aptos-style) — INTENTIONAL VULNERABILITIES for scanner testing.
// Missing `acquires` annotation, ability mismatch, capability leak.

module test::vault {
    use std::signer;
    use aptos_framework::coin;
    use aptos_framework::event;

    /// VULN: missing `key` ability — this resource is a "hot potato"
    ///        and cannot be stored on-chain, leading to permanent
    ///        loss when the function aborts.
    struct Vault has store, drop {
        owner: address,
        balance: u64,
    }

    /// VULN: capability stored in a publicly-readable resource.
    struct AdminCap has key, copy, drop, store {
        addr: address,
    }

    #[event]
    struct DepositEvent has drop, store { addr: address, amount: u64 }

    public entry fun deposit(account: &signer, amount: u64) {
        let addr = signer::address_of(account);
        // VULN: missing acquires — would abort at runtime
        let _vault = borrow_global<Vault>(addr);
        event::emit(DepositEvent { addr, amount });
    }

    /// VULN: capability leak — returns the AdminCap by value
    public fun steal_cap(admin: &signer): AdminCap acquires AdminCap {
        let cap = move_from<AdminCap>(signer::address_of(admin));
        cap
    }

    public fun init_cap(account: &signer) {
        move_to(account, AdminCap { addr: signer::address_of(account) });
    }
}
