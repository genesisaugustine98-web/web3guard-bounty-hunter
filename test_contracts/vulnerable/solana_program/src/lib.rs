// Solana / Anchor test program — INTENTIONAL VULNERABILITIES for scanner testing.
// Missing owner check, missing signer, account substitution, PDA seed weakness.

use anchor_lang::prelude::*;
use anchor_lang::system_program;

declare_id!("Vau1tXXXXXAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

#[program]
pub mod vulnerable_vault {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        // VULN: missing owner check — anyone can reinitialize
        let vault = &mut ctx.accounts.vault;
        vault.owner = ctx.accounts.user.key();
        vault.balance = 0;
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // VULN: missing signer check on the beneficiary account
        let vault = &mut ctx.accounts.vault;
        require!(vault.balance >= amount, VaultError::InsufficientFunds);

        // VULN: account substitution — the `to` account is unverified
        // AccountInfo. A user can pass any account that "looks like"
        // a system account but is actually a token program or PDA.
        let _ = ctx.accounts.to.to_account_info();
        **vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.to.to_account_info().try_borrow_mut_lamports()? += amount;
        vault.balance -= amount;
        Ok(())
    }

    pub fn close_account(ctx: Context<CloseAccount>) -> Result<()> {
        // VULN: closing an account that still has lamports — leaves
        // "ghost" lamports that can't be recovered.
        let dest = ctx.accounts.destination.to_account_info();
        **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? = 0;
        **dest.try_borrow_mut_lamports()? += ctx.accounts.vault.to_account_info().lamports();
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = user, space = 8 + 32 + 8)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// CHECK: missing owner check
    #[account(mut)]
    pub to: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CloseAccount<'info> {
    #[account(mut, close = destination)]
    pub vault: Account<'info, Vault>,
    pub destination: Signer<'info>,
}

#[account]
pub struct Vault {
    pub owner: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum VaultError {
    #[msg("Insufficient funds")]
    InsufficientFunds,
}
