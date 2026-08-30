// Solana / Anchor clean program - initialize guarded, all accounts
// are typed Account<>, lamports via system_program.
use anchor_lang::prelude::*;

declare_id!("Safe111111111111111111111111111111111111111");

#[program]
pub mod safe_vault {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        require!(!vault.initialized, VaultError::AlreadyInitialized);
        vault.initialized = true;
        vault.owner = ctx.accounts.user.key();
        vault.balance = 0;
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        require!(vault.balance >= amount, VaultError::InsufficientFunds);
        vault.balance -= amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = user, space = 8 + 32 + 8 + 1)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = owner)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub owner: Signer<'info>,
}

#[account]
pub struct Vault {
    pub initialized: bool,
    pub owner: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum VaultError {
    #[msg("Already initialized")]
    AlreadyInitialized,
    #[msg("Insufficient funds")]
    InsufficientFunds,
}
