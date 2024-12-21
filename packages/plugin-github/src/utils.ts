import fs from "fs/promises";
import path from "path";
import { glob } from "glob";
import { existsSync } from "fs";
import simpleGit from "simple-git";
import { Octokit } from "@octokit/rest";
import { elizaLogger, IAgentRuntime, Memory, State, stringToUuid, UUID } from "@ai16z/eliza";

export function getRepoPath(owner: string, repo: string) {
    return path.join(process.cwd(), ".repos", owner, repo);
}

export async function createReposDirectory(owner: string) {
    const dirPath = path.join(process.cwd(), ".repos", owner);
    if (existsSync(dirPath)) {
        elizaLogger.info(`Repos directory already exists: ${dirPath}`);
        return;
    }
    try {
        // Create repos directory
        await fs.mkdir(dirPath, {
            recursive: true,
        });
    } catch (error) {
        elizaLogger.error("Error creating repos directory:", error);
        throw new Error(`Error creating repos directory: ${error}`);
    }
}

export async function cloneOrPullRepository(
    owner: string,
    repo: string,
    repoPath: string,
    branch: string = "main"
) {
    try {
        elizaLogger.info(
            `Cloning or pulling repository ${owner}/${repo}... @ branch: ${branch}`
        );
        elizaLogger.info(
            `URL: https://github.com/${owner}/${repo}.git @ branch: ${branch}`
        );

        // Clone or pull repository
        if (!existsSync(repoPath)) {
            const git = simpleGit();
            await git.clone(
                `https://github.com/${owner}/${repo}.git`,
                repoPath,
                {
                    "--branch": branch,
                }
            );
        } else {
            const git = simpleGit(repoPath);
            await git.pull();
        }
    } catch (error) {
        elizaLogger.error(
            `Error cloning or pulling repository ${owner}/${repo}:`,
            error
        );
        throw new Error(`Error cloning or pulling repository: ${error}`);
    }
}

export async function writeFiles(
    repoPath: string,
    files: Array<{ path: string; content: string }>
) {
    try {
        // check if the local repo exists
        if (!existsSync(repoPath)) {
            elizaLogger.error(
                `Repository ${repoPath} does not exist locally. Please initialize the repository first.`
            );
            throw new Error(
                `Repository ${repoPath} does not exist locally. Please initialize the repository first.`
            );
        }

        for (const file of files) {
            const filePath = path.join(repoPath, file.path);
            await fs.mkdir(path.dirname(filePath), { recursive: true });
            await fs.writeFile(filePath, file.content);
        }
    } catch (error) {
        elizaLogger.error("Error writing files:", error);
        throw new Error(`Error writing files: ${error}`);
    }
}

interface CommitAndPushChangesResponse {
    hash: string;
}

export async function commitAndPushChanges(
    repoPath: string,
    message: string,
    branch?: string
) {
    try {
        const git = simpleGit(repoPath);
        await git.add(".");
        const commit = await git.commit(message);
        if (branch) {
            await git.push("origin", branch);
        } else {
            await git.push();
        }
        return {
            hash: commit.commit,
        } as CommitAndPushChangesResponse;
    } catch (error) {
        elizaLogger.error("Error committing and pushing changes:", error);
        throw new Error(`Error committing and pushing changes: ${error}`);
    }
}

export async function checkoutBranch(
    repoPath: string,
    branch?: string,
    create: boolean = false
) {
    if (!branch) {
        return;
    }

    elizaLogger.info(`Checking out branch ${branch} in repository ${repoPath}`);

    try {
        const git = simpleGit(repoPath);

        // Get the list of branches
        const branchList = await git.branch();

        // Check if the branch exists
        const branchExists = branchList.all.includes(branch);

        if (create) {
            if (branchExists) {
                elizaLogger.warn(
                    `Branch "${branch}" already exists. Checking out instead.`
                );
                await git.checkout(branch); // Checkout the existing branch
            } else {
                // Create a new branch
                await git.checkoutLocalBranch(branch);
            }
        } else {
            if (!branchExists) {
                throw new Error(`Branch "${branch}" does not exist.`);
            }
            // Checkout an existing branch
            await git.checkout(branch);
        }
    } catch (error) {
        elizaLogger.error("Error checking out branch:", error.message);
        throw new Error(`Error checking out branch: ${error.message}`);
    }
}

interface CreatePullRequestResponse {
    url: string;
}

export async function createPullRequest(
    token: string,
    owner: string,
    repo: string,
    branch: string,
    title: string,
    description?: string,
    base?: string
) {
    try {
        const octokit = new Octokit({
            auth: token,
        });

        const pr = await octokit.pulls.create({
            owner,
            repo,
            title,
            body: description || title,
            head: branch,
            base: base || "main",
        });

        return {
            url: pr.data.html_url,
        } as CreatePullRequestResponse;
    } catch (error) {
        elizaLogger.error("Error creating pull request:", error);
        throw new Error(`Error creating pull request: ${error}`);
    }
}

export async function retrieveFiles(repoPath: string, gitPath: string) {
    // Build the search path
    const searchPath = gitPath
        ? path.join(repoPath, gitPath, "**/*")
        : path.join(repoPath, "**/*");
    elizaLogger.info(`Repo path: ${repoPath}`);
    elizaLogger.info(`Search path: ${searchPath}`);
    // Exclude `.git` directory
    const ignorePatterns = ["**/.git/**"];

    // Check if a .gitignore file exists
    const gitignorePath = path.join(repoPath, ".gitignore");
    if (existsSync(gitignorePath)) {
        const gitignoreContent = await fs.readFile(gitignorePath, "utf-8");
        const gitignoreLines = gitignoreContent
            .split("\n")
            .map((line) => line.trim())
            .filter(
                (line) => line && !line.startsWith("#") && !line.startsWith("!")
            ) // Exclude comments and lines starting with '!'
            .map((line) => `**/${line}`); // Convert to glob patterns

        ignorePatterns.push(...gitignoreLines);
    }

    elizaLogger.info(`Ignore patterns:\n${ignorePatterns.join("\n")}`);

    const files = await glob(searchPath, {
        nodir: true,
        dot: true, // Include dotfiles
        ignore: ignorePatterns, // Exclude .git and .gitignore patterns
    });

    elizaLogger.info(`Retrieved Files:\n${files.join("\n")}`);

    return files;
}

export const getFilesFromMemories = async (
    runtime: IAgentRuntime,
    message: Memory
) => {
    const allMemories = await runtime.messageManager.getMemories({
        roomId: message.roomId,
    });
    // elizaLogger.info("All Memories:", allMemories);
    const memories = allMemories.filter(
        (memory) => (memory.content.metadata as any)?.path
    );
    elizaLogger.info("Memories:", memories);
    return memories.map(
        (memory) => `File: ${(memory.content.metadata as any)?.path}
        Content: ${memory.content.text.replace(/\n/g, "\\n")}
        `
    );
};

export async function getIssuesFromMemories(runtime: IAgentRuntime, owner: string, repo: string): Promise<Memory[]> {
    const roomId = stringToUuid(`github-${owner}-${repo}`);
    const memories = await runtime.messageManager.getMemories({
        roomId: roomId,
    });
    elizaLogger.log("Memories:", memories);
    // Filter memories to only include those that are issues
    const issueMemories = memories.filter(memory => (memory.content.metadata as any)?.type === "issue");
    return issueMemories;
}

export async function incorporateRepositoryState(state: State, runtime: IAgentRuntime, message: Memory) {
    const files = await getFilesFromMemories(runtime, message);
    // add additional keys to state
    state.files = files;
    state.character = JSON.stringify(runtime.character || {}, null, 2);
    const owner = runtime.getSetting("GITHUB_OWNER") ?? '' as string;
    state.owner = owner;
    const repository = runtime.getSetting("GITHUB_REPO") ?? '' as string;
    state.repository = repository;
    if (owner === '' || repository === '') {
        elizaLogger.error("GITHUB_OWNER or GITHUB_REPO is not set, skipping OODA cycle.");
        throw new Error("GITHUB_OWNER or GITHUB_REPO is not set");
    }
    const previousIssues = await getIssuesFromMemories(runtime, owner, repository);
    state.previousIssues = JSON.stringify(previousIssues.map(issue => ({
        title: issue.content.text,
        body: (issue.content.metadata as any).body,
        url: (issue.content.metadata as any).url,
        number: (issue.content.metadata as any).number,
        state: (issue.content.metadata as any).state,
    })), null, 2);
    elizaLogger.log("Previous issues:", state.previousIssues);
    elizaLogger.info("State:", state);
    const previousPRs = await getPullRequestsFromMemories(runtime, owner, repository);
    state.previousPRs = JSON.stringify(previousPRs.map(pr => ({
        title: pr.content.text,
        body: (pr.content.metadata as any).body,
        url: (pr.content.metadata as any).url,
        number: (pr.content.metadata as any).number,
        state: (pr.content.metadata as any).state,
    })), null, 2);
    return state;
}

export async function getPullRequestsFromMemories(runtime: IAgentRuntime, owner: string, repo: string): Promise<Memory[]> {
    const roomId = stringToUuid(`github-${owner}-${repo}`);
    const memories = await runtime.messageManager.getMemories({
        roomId: roomId,
    });
    // Filter memories to only include those that are pull requests
    const prMemories = memories.filter(memory => (memory.content.metadata as any)?.type === "pull_request");
    return prMemories;
}

export const getRepositoryRoomId = (runtime: IAgentRuntime): UUID => {
    const owner = runtime.getSetting("GITHUB_OWNER") ?? '' as string;
    const repository = runtime.getSetting("GITHUB_REPO") ?? '' as string;
    if (owner === '' || repository === '') {
        elizaLogger.error("GITHUB_OWNER or GITHUB_REPO is not set, skipping OODA cycle.");
        throw new Error("GITHUB_OWNER or GITHUB_REPO is not set");
    }
    const roomId = stringToUuid(`github-${owner}-${repository}`);
    elizaLogger.log("Generated repository room ID:", roomId);
    return roomId;
}