// Solana / Anchor test program - INTENTIONAL VULNERABILITIES:
// unguarded initialize + unverified AccountInfo.
use anchor_lang::prelude::*;

declare_id!("Admi111111111111111111111111111111111111111");

#[program]
pub mod admin_registry {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        // VULN: no guard - anyone can reinitialize.
        let registry = &mut ctx.accounts.registry;
        registry.owner = ctx.accounts.authority.key();
        Ok(())
    }

    pub fn set_admin(ctx: Context<SetAdmin>) -> Result<()> {
        let registry = &mut ctx.accounts.registry;
        registry.owner = ctx.accounts.new_admin.key();
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + 32)]
    pub registry: Account<'info, Registry>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetAdmin<'info> {
    #[account(mut)]
    pub registry: Account<'info, Registry>,
    /// CHECK: VULN - unverified account accepted by reference
    #[account(mut)]
    pub new_admin: AccountInfo<'info>,
}

#[account]
pub struct Registry {
    pub owner: Pubkey,
}
