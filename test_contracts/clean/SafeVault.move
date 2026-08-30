// SPDX-License-Identifier: MIT
// Clean Move vault (Aptos-style) - acquires annotations present,
// no copyable capabilities, storage persisted via move_to only.
module test::safe_vault {
    use std::signer;

    struct Vault has key {
        owner: address,
        balance: u64,
    }

    public entry fun deposit(account: &signer, amount: u64) acquires Vault {
        assert!(amount > 0, 1);
        let addr = signer::address_of(account);
        let vault = Vault { owner: addr, balance: amount };
        move_to(account, vault);
    }

    public entry fun withdraw(account: &signer, amount: u64) acquires Vault {
        assert!(amount > 0, 1);
        let addr = signer::address_of(account);
        let vault = Vault { owner: addr, balance: 0 };
        move_to(account, vault);
    }

    public fun init(account: &signer) {
        move_to(account, Vault { owner: signer::address_of(account), balance: 0 });
    }
}
