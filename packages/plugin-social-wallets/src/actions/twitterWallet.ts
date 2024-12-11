import {
    elizaLogger,
    Memory,
    type Action,
    IAgentRuntime,
    State,
    composeContext,
    ModelClass,
    generateObjectV2,
    HandlerCallback,
} from "@ai16z/eliza";
import { PrivyProvider } from "../providers/privy";
import { TwitterTemplate } from "../templates";
import {
    isTwitterUsernameContent,
    TwitterUsernameContent,
    TwitterUsernameSchema,
} from "../types";
import { SimpleTwitterManager } from "@ai16z/client-twitter";

export class PrivyTwitterWalletAction {
    privyProvider: PrivyProvider;
    agentRuntime: IAgentRuntime;

    constructor(privyProvider: PrivyProvider, agentRuntime: IAgentRuntime) {
        this.privyProvider = privyProvider;
        this.agentRuntime = agentRuntime;
    }

    async getTwitterUserWallet(twitterUsername: string) {
        try {
            elizaLogger.log(
                "TRYING TO GET WALLET FOR TWITTER USER " + twitterUsername
            );
            let user: any =
                await this.privyProvider.getUserByTwitterUsername(
                    twitterUsername
                );
            if (!user) {
                user = await this.createWalletForTwitterUser(twitterUsername);
            }
            const wallets = [];
            for (const account of user.linked_accounts) {
                if (account.type === "wallet") {
                    wallets.push({
                        chain: account.chain_type,
                        address: account.address,
                    });
                }
            }
            return wallets;
        } catch (error) {
            elizaLogger.error("Unable to get wallet for twitter user:", error);
        }
    }

    async createWalletForTwitterUser(twitterUsername: string) {
        elizaLogger.log(
            `WALLET FOR TWITTER USER ${twitterUsername} NOT FOUND. CREATING WALLET INSTEAD`
        );

        if (
            !this.agentRuntime.getSetting("TWITTER_USERNAME") ||
            !this.agentRuntime.getSetting("TWITTER_PASSWORD") ||
            !this.agentRuntime.getSetting("TWITTER_EMAIL")
        ) {
            elizaLogger.error(
                "Twitter credentials not found. Required to pull down data on twitter user."
            );
            return;
        }
        try {
            const twitter = new SimpleTwitterManager(this.agentRuntime);
            while (true) {
                await twitter.client.twitterClient.login(
                    this.agentRuntime.getSetting("TWITTER_USERNAME"),
                    this.agentRuntime.getSetting("TWITTER_PASSWORD"),
                    this.agentRuntime.getSetting("TWITTER_EMAIL"),
                    this.agentRuntime.getSetting("TWITTER_2FA_SECRET") ||
                        undefined
                );
                if (await twitter.client.twitterClient.isLoggedIn()) {
                    break;
                }

                elizaLogger.error("Failed to login to Twitter trying again...");
                await new Promise((resolve) => setTimeout(resolve, 2000));
            }

            const twitterUser =
                await twitter.client.fetchProfile(twitterUsername);

            const privyUser = await this.privyProvider.createTwitterUser({
                type: "twitter_oauth",
                profilePictureUrl: twitter.avatar,
                username: twitterUser.username,
                subject: twitterUser.id,
                name: twitterUser.screenName,
            });

            return privyUser;
        } catch (error) {
            elizaLogger.error(
                "Unable to create wallet for twitter user:",
                error
            );
        }
    }
}

export const getWalletForTwitter: Action = {
    name: "GET_WALLET_ADDRESS_FOR_TWITTER_USERNAME",
    description: "Get wallet address for a twitter usernane",
    validate: async (runtime: IAgentRuntime, _message: Memory) => {
        elizaLogger.log(
            "Validating runtime for GET_WALLET_ADDRESS_FOR_TWITTER_USERNAME..."
        );
        return (
            !!(
                runtime.character.settings.secrets?.PRIVY_APP_ID ||
                process.env.PRIVY_APP_ID
            ) &&
            !!(
                runtime.character.settings.secrets?.PRIVY_APP_SECRET ||
                process.env.PRIVY_APP_SECRET
            )
        );
    },
    handler: async (
        runtime: IAgentRuntime,
        _message: Memory,
        state: State,
        _options: any,
        callback: HandlerCallback
    ) => {
        elizaLogger.log(
            "Starting GET_WALLET_ADDRESS_FOR_TWITTER_USERNAME handler..."
        );

        const context = composeContext({
            state,
            template: TwitterTemplate,
        });

        const twitterDetails = await generateObjectV2({
            runtime,
            context,
            modelClass: ModelClass.SMALL,
            schema: TwitterUsernameSchema,
        });

        if (!isTwitterUsernameContent(twitterDetails.object)) {
            callback(
                {
                    text: "Invalid twitter details. Ensure the username is specified.",
                },
                []
            );
            return;
        }

        const { username } = twitterDetails.object as TwitterUsernameContent;
        const privyProvider = new PrivyProvider(runtime);

        const action = new PrivyTwitterWalletAction(privyProvider, runtime);
        const wallets = await action.getTwitterUserWallet(username);

        callback({
            text: `@${username} wallet addresses are ${wallets.map((item) => `${item.chain}:${item.address}`).join(" ")}`,
            content: {
                success: true,
            },
        });
    },
    examples: [
        [
            {
                user: "{{user1}}",
                content: {
                    text: "What is wallet address of @elonmusk",
                    action: "GET_WALLET_ADDRESS_FOR_TWITTER_USERNAME",
                },
            },
            {
                user: "{{agentName}}",
                content: {
                    text: "@elonmusk wallet address is 0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                    action: "GET_WALLET_ADDRESS_FOR_TWITTER_USERNAME",
                },
            },
        ],
        [
            {
                user: "{{user1}}",
                content: {
                    text: "im looking for wallet address for @elonmusk",
                    action: "GET_WALLET_ADDRESS_FOR_TWITTER_USERNAME",
                },
            },
            {
                user: "{{agentName}}",
                content: {
                    text: "@elonmusk wallet address is 0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                    action: "GET_WALLET_ADDRESS_FOR_TWITTER_USERNAME",
                },
            },
        ],
        [
            {
                user: "{{user1}}",
                content: {
                    text: "can you help me find @elonmusk wallet address",
                    action: "GET_WALLET_ADDRESS_FOR_TWITTER_USERNAME",
                },
            },
            {
                user: "{{agentName}}",
                content: {
                    text: "@elonmusk wallet address is 0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                    action: "GET_WALLET_ADDRESS_FOR_TWITTER_USERNAME",
                },
            },
        ],
    ],
    similes: ["GET_WALLET_FOR_TWITTER", "GET_TWITTER_WALLET_ADDRESS"],
};
