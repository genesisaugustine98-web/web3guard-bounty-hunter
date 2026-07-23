// Cairo / Starknet test contract — INTENTIONAL VULNERABILITIES for scanner testing.
// get_caller_address vs get_execution_info.caller_addr confusion, L1<>L2 message bugs.

#[starknet::contract]
mod VulnerableL1L2 {
    use starknet::{get_caller_address, get_execution_info};
    use starknet::ContractAddress;
    use core::array::ArrayTrait;
    use core::option::OptionTrait;
    use core::traits::Into;

    #[storage]
    struct Storage {
        owner: ContractAddress,
        pending_l1_messages: LegacyMap::<felt252, felt252>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.owner.write(owner);
    }

    // VULN: get_caller_address() vs get_execution_info().caller_addr confusion
    // get_caller_address() is the *immediate* caller (a contract could be
    // calling us on behalf of an L1 user). get_execution_info().caller_addr
    // is the *original* L1 caller. Confusing them lets a malicious
    // contract impersonate users.
    #[external(v0)]
    fn withdraw(ref self: ContractState, amount: u128) {
        let caller = get_caller_address();
        // VULN: should be get_execution_info().caller_addr
        assert(caller == self.owner.read(), 'not owner');
        // ... send funds
    }

    // VULN: L1->L2 message handling without a nonce
    #[l1_handler]
    fn handle_l1_message(
        ref self: ContractState,
        from_address: felt252,
        message: felt252,
    ) {
        // VULN: no replay protection — same L1 message can be processed
        // multiple times if the L2 sequencer re-executes.
        let _ = from_address;
        self.pending_l1_messages.write(from_address, message);
    }
}
