// Cairo / Starknet test contract - CLEAN: uses execution_info
// caller (not get_caller_address), and l1_handler has a nonce.
#[starknet::contract]
mod SafeVault {
    use starknet::{get_execution_info, ContractAddress};
    use starknet::contract_address::ContractAddressZeroable;
    use core::traits::Into;

    #[storage]
    struct Storage {
        owner: ContractAddress,
        balance: u128,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.owner.write(owner);
    }

    #[external(v0)]
    fn withdraw(ref self: ContractState, amount: u128) {
        let info = get_execution_info().unbox();
        let caller = *info.caller_address;
        assert(caller == self.owner.read(), 'not owner');
        assert(self.balance.read() >= amount, 'insufficient');
        self.balance.write(self.balance.read() - amount);
    }

    #[external(v0)]
    fn deposit(ref self: ContractState, amount: u128) {
        self.balance.write(self.balance.read() + amount);
    }
}
