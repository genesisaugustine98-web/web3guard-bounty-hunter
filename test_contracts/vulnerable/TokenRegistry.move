// SPDX-License-Identifier: MIT
// INTENTIONAL VULNERABILITIES: copyable capability + missing acquires.
module test::token_registry {
    use std::signer;

    // VULN: copyable admin capability.
    struct AdminCap has key, copy, store {
        addr: address,
    }

    struct Registry has key {
        admin: address,
    }

    public entry fun register(account: &signer, token: address) {
        let addr = signer::address_of(account);
        // VULN: missing acquires annotation -> runtime abort.
        let _reg = borrow_global<Registry>(addr);
        let _ = token;
    }

    public fun init_cap(account: &signer) {
        move_to(account, AdminCap { addr: signer::address_of(account) });
    }

    public fun init_registry(account: &signer) {
        move_to(account, Registry { admin: signer::address_of(account) });
    }
}
