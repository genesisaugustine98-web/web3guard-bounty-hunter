// Cairo / Starknet test contract - INTENTIONAL VULNERABILITY:
// L1->L2 handler without replay protection.
#[starknet::contract]
mod L1Bridge {
    use starknet::ContractAddress;
    use core::array::ArrayTrait;

    #[storage]
    struct Storage {
        deposited: LegacyMap::<ContractAddress, u128>,
    }

    // VULN: no nonce or dedup - an L1 message can be re-executed.
    #[l1_handler]
    fn handle_l1_deposit(
        ref self: ContractState,
        from_address: ContractAddress,
        amount: u128,
    ) {
        self.deposited.write(from_address, amount);
    }
}
