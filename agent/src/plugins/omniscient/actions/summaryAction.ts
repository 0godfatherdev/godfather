import {
    Action,
    HandlerCallback,
    IAgentRuntime,
    Memory,
    State,
} from "@ai16z/eliza";
import { generateDirectResponse } from "../../../utils/messageGenerator";
import { OmniscientProvider } from "../providers/omniscientProvider";

const summaryTemplate = `Given the following project data, provide a focused summary:

Project Data:
🚀 Active Projects:
{{projects}}

⚠️ Critical Issues:
{{criticalIssues}}

👥 Teams:
{{teams}}

📋 All Issues:
{{issues}}

Last Updated: {{lastUpdated}}

Guidelines:
- Highlight critical issues and their priorities
- Focus on active project progress
- Note team assignments and workload distribution
- Identify any bottlenecks or risks
- Keep response concise and actionable
- Prioritize by impact and urgency`;

export const summaryAction: Action = {
    name: "SUMMARIZE_CONTEXT",
    description: "Summarizes project context and priorities",
    similes: ["SUMMARIZE", "GET_OVERVIEW", "CHECK_STATUS"],
    validate: async (runtime: IAgentRuntime, message: Memory, state: State) => {
        return true;
    },
    handler: async (
        runtime: IAgentRuntime,
        message: Memory,
        state: State,
        _options: unknown,
        callback: HandlerCallback
    ) => {
        const provider = new OmniscientProvider(runtime);
        const data = await provider.getData();

        if (!data) {
            return generateDirectResponse(
                runtime,
                state,
                callback,
                {},
                "No project data available",
                { error: "No project data available" }
            );
        }

        const criticalIssues = data.issues.filter((i) => i.priority >= 2);

        return generateDirectResponse(
            runtime,
            state,
            callback,
            {
                projects: data.projects,
                criticalIssues,
                teams: data.teams,
                issues: data.issues,
                lastUpdated: new Date(data.lastUpdated).toLocaleString(),
            },
            summaryTemplate,
            {
                success: true,
                data: { summary: data },
            }
        );
    },
    examples: [
        [
            {
                user: "{{user1}}",
                content: {
                    text: "What are our current priorities?",
                },
            },
            {
                user: "{{user2}}",
                content: {
                    text: "Based on the project data, here are the key priorities...",
                    action: "SUMMARIZE_CONTEXT",
                },
            },
        ],
    ],
};
