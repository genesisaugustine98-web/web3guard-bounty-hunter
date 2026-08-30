// INTENTIONAL VULNERABILITIES: zero-slippage swap + unlimited approval.
import { ethers } from "ethers";

const provider = new ethers.JsonRpcProvider(process.env.RPC_URL!);
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY!, provider);

const TOKEN_ADDRESS = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"; // USDC
const ROUTER_ADDRESS = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"; // Uniswap V2

async function swap(tokenIn: string, amountIn: bigint) {
  // VULN: minOut passed as positional 0 - sandwichable.
  const tx = await ROUTER(tokenIn, TOKEN_ADDRESS).swapExactTokensForTokens(
    amountIn,
    0,
    [tokenIn, TOKEN_ADDRESS],
    wallet.address,
    Math.floor(Date.now() / 1000) + 60 * 20
  );
  return await tx.wait();
}

async function approve(spender: string) {
  // VULN: unlimited approval.
  const token = new ethers.Contract(TOKEN_ADDRESS, ERC20_ABI, wallet);
  const tx = await token.approve(spender, ethers.MaxUint256);
  return await tx.wait();
}

export { swap, approve };
