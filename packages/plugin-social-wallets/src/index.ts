import { Plugin } from "@ai16z/eliza";
import { getWalletForTwitter } from "./actions/twitterWallet";
import { privyProvider } from "./providers/privy";

export const socialWalletsPlugin: Plugin = {
    name: "Social Wallets Plugin",
    description: "get wallets for social handles using privy",
    actions: [getWalletForTwitter],
    providers: [privyProvider],
};

export default socialWalletsPlugin;
