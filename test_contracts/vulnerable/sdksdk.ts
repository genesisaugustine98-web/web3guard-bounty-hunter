// TypeScript / off-chain SDK test — INTENTIONAL VULNERABILITIES for scanner testing.
// Slippage = 0, MAX_UINT256 approval, hardcoded RPC URL, permit front-running.

import { ethers } from "ethers";

const PROVIDER = new ethers.JsonRpcProvider(
  // VULN: hardcoded RPC URL with API key
  "https://eth-mainnet.g.alchemy.com/v2/abcd1234EFGH5678ijkl9012mnop"
);

const WALLET = new ethers.Wallet(process.env.PRIVATE_KEY!, PROVIDER);

const TOKEN_ADDRESS = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"; // USDC
const ROUTER_ADDRESS = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"; // Uniswap V2

async function swapWithZeroSlippage(tokenIn: string, amountIn: bigint) {
  // VULN: minOut = 0 — sandwich attack drains the user
  const tx = await ROUTER(tokenIn, TOKEN_ADDRESS).swapExactTokensForTokens(
    amountIn,
    0,  // <-- minOut = 0
    [tokenIn, TOKEN_ADDRESS],
    WALLET.address,
    Math.floor(Date.now() / 1000) + 60 * 20
  );
  return await tx.wait();
}

async function approveUnlimited(spender: string) {
  // VULN: unlimited approval — spender can drain later if compromised
  const token = new ethers.Contract(TOKEN_ADDRESS, ERC20_ABI, WALLET);
  const tx = await token.approve(
    spender,
    ethers.MaxUint256  // <-- MAX_UINT256
  );
  return await tx.wait();
}

async function submitPermit(permit: any) {
  // VULN: permit front-running — anyone can submit the permit
  // before the legitimate user does
  const token = new ethers.Contract(permit.token, ERC20_ABI, PROVIDER);
  await token.permit(
    permit.owner,
    permit.spender,
    permit.value,
    permit.deadline,
    permit.v,
    permit.r,
    permit.s
  );
}

export { swapWithZeroSlippage, approveUnlimited, submitPermit };
