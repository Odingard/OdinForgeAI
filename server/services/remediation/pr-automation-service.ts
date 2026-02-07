import { Octokit } from "@octokit/rest";
import { Gitlab } from "@gitbeaker/node";
import type { PRRequest, PRResult, FileChange } from "./iac-remediation-service";

interface GitConfig {
  provider: "github" | "gitlab";
  token: string;
  baseUrl?: string; // For GitLab self-hosted or GitHub Enterprise
}

interface GitHubRepoInfo {
  owner: string;
  repo: string;
}

interface GitLabProjectInfo {
  projectId: string;
}

class PRAutomationService {
  private githubClient: Octokit | null = null;
  private gitlabClient: InstanceType<typeof Gitlab> | null = null;
  private config: GitConfig | null = null;

  /**
   * Initialize the PR automation service with credentials
   */
  configure(config: GitConfig): void {
    this.config = config;

    if (config.provider === "github") {
      this.githubClient = new Octokit({
        auth: config.token,
        baseUrl: config.baseUrl || "https://api.github.com",
      });
    } else if (config.provider === "gitlab") {
      this.gitlabClient = new Gitlab({
        token: config.token,
        host: config.baseUrl || "https://gitlab.com",
      });
    }
  }

  /**
   * Create a Pull Request on GitHub
   */
  private async createGitHubPR(request: PRRequest): Promise<PRResult> {
    if (!this.githubClient) {
      throw new Error("GitHub client not configured. Call configure() first.");
    }

    const repoInfo = this.parseGitHubUrl(request.repositoryUrl);
    const branchName = request.branchName || `odinforge-fix-${Date.now()}`;

    try {
      // 1. Get the default branch
      const { data: repo } = await this.githubClient.repos.get({
        owner: repoInfo.owner,
        repo: repoInfo.repo,
      });
      const defaultBranch = repo.default_branch;

      // 2. Get the latest commit SHA from default branch
      const { data: ref } = await this.githubClient.git.getRef({
        owner: repoInfo.owner,
        repo: repoInfo.repo,
        ref: `heads/${defaultBranch}`,
      });
      const latestCommitSha = ref.object.sha;

      // 3. Create a new branch
      await this.githubClient.git.createRef({
        owner: repoInfo.owner,
        repo: repoInfo.repo,
        ref: `refs/heads/${branchName}`,
        sha: latestCommitSha,
      });

      // 4. Create/update files
      for (const change of request.changes) {
        let existingFileSha: string | undefined;

        // Check if file exists
        try {
          const { data: fileData } = await this.githubClient.repos.getContent({
            owner: repoInfo.owner,
            repo: repoInfo.repo,
            path: change.filePath,
            ref: branchName,
          });

          if ("sha" in fileData) {
            existingFileSha = fileData.sha;
          }
        } catch (error: any) {
          // File doesn't exist, will be created
          if (error.status !== 404) {
            throw error;
          }
        }

        if (change.changeType === "delete") {
          if (existingFileSha) {
            await this.githubClient.repos.deleteFile({
              owner: repoInfo.owner,
              repo: repoInfo.repo,
              path: change.filePath,
              message: `Delete ${change.filePath}`,
              sha: existingFileSha,
              branch: branchName,
            });
          }
        } else {
          // Create or update file
          await this.githubClient.repos.createOrUpdateFileContents({
            owner: repoInfo.owner,
            repo: repoInfo.repo,
            path: change.filePath,
            message: change.changeType === "create"
              ? `Add ${change.filePath}`
              : `Update ${change.filePath}`,
            content: Buffer.from(change.content).toString("base64"),
            branch: branchName,
            sha: existingFileSha,
          });
        }
      }

      // 5. Create Pull Request
      const { data: pr } = await this.githubClient.pulls.create({
        owner: repoInfo.owner,
        repo: repoInfo.repo,
        title: request.title,
        body: request.description,
        head: branchName,
        base: defaultBranch,
      });

      // 6. Add labels if provided
      if (request.labels && request.labels.length > 0) {
        await this.githubClient.issues.addLabels({
          owner: repoInfo.owner,
          repo: repoInfo.repo,
          issue_number: pr.number,
          labels: request.labels,
        });
      }

      // 7. Request reviewers if provided
      if (request.reviewers && request.reviewers.length > 0) {
        await this.githubClient.pulls.requestReviewers({
          owner: repoInfo.owner,
          repo: repoInfo.repo,
          pull_number: pr.number,
          reviewers: request.reviewers,
        });
      }

      return {
        id: `gh-pr-${pr.number}`,
        status: "created",
        url: pr.html_url,
        branchName,
        title: request.title,
        filesChanged: request.changes.length,
        rollbackCommit: latestCommitSha,
      };
    } catch (error: any) {
      console.error("[PRAutomation] GitHub PR creation failed:", error);
      throw new Error(`Failed to create GitHub PR: ${error.message}`);
    }
  }

  /**
   * Create a Merge Request on GitLab
   */
  private async createGitLabMR(request: PRRequest): Promise<PRResult> {
    if (!this.gitlabClient) {
      throw new Error("GitLab client not configured. Call configure() first.");
    }

    const projectInfo = this.parseGitLabUrl(request.repositoryUrl);
    const branchName = request.branchName || `odinforge-fix-${Date.now()}`;

    try {
      // 1. Get project details
      const project = await this.gitlabClient.Projects.show(projectInfo.projectId);
      const defaultBranch = project.default_branch || "main";

      // 2. Create a new branch
      await this.gitlabClient.Branches.create(
        projectInfo.projectId,
        branchName,
        defaultBranch
      );

      // 3. Create commits for file changes
      const actions = request.changes.map((change) => ({
        action: change.changeType === "delete"
          ? "delete"
          : change.changeType === "create"
          ? "create"
          : "update",
        file_path: change.filePath,
        content: change.content,
      }));

      await this.gitlabClient.Commits.create(
        projectInfo.projectId,
        branchName,
        "Apply OdinForge security remediation",
        actions as any
      );

      // 4. Create Merge Request
      const mr = await this.gitlabClient.MergeRequests.create(
        projectInfo.projectId,
        branchName,
        defaultBranch,
        request.title,
        {
          description: request.description,
          labels: request.labels?.join(","),
          assignee_ids: request.reviewers?.map((r) => parseInt(r, 10)).filter((id) => !isNaN(id)),
        }
      );

      return {
        id: `gl-mr-${mr.iid}`,
        status: "created",
        url: mr.web_url,
        branchName,
        title: request.title,
        filesChanged: request.changes.length,
        rollbackCommit: defaultBranch,
      };
    } catch (error: any) {
      console.error("[PRAutomation] GitLab MR creation failed:", error);
      throw new Error(`Failed to create GitLab MR: ${error.message}`);
    }
  }

  /**
   * Create a PR/MR based on configured provider
   */
  async createPullRequest(request: PRRequest): Promise<PRResult> {
    if (!this.config) {
      throw new Error("PR automation service not configured. Call configure() first.");
    }

    if (this.config.provider === "github") {
      return this.createGitHubPR(request);
    } else if (this.config.provider === "gitlab") {
      return this.createGitLabMR(request);
    }

    throw new Error(`Unsupported provider: ${this.config.provider}`);
  }

  /**
   * Parse GitHub repository URL
   * Supports: https://github.com/owner/repo, git@github.com:owner/repo.git
   */
  private parseGitHubUrl(url: string): GitHubRepoInfo {
    const httpsMatch = url.match(/github\.com\/([^\/]+)\/([^\/\.]+)/);
    if (httpsMatch) {
      return {
        owner: httpsMatch[1],
        repo: httpsMatch[2],
      };
    }

    const sshMatch = url.match(/git@github\.com:([^\/]+)\/([^\/\.]+)/);
    if (sshMatch) {
      return {
        owner: sshMatch[1],
        repo: sshMatch[2],
      };
    }

    throw new Error(`Invalid GitHub repository URL: ${url}`);
  }

  /**
   * Parse GitLab repository URL
   * Supports: https://gitlab.com/group/project, git@gitlab.com:group/project.git
   */
  private parseGitLabUrl(url: string): GitLabProjectInfo {
    const httpsMatch = url.match(/gitlab\.com\/([^\/]+\/[^\/\.]+)/);
    if (httpsMatch) {
      return {
        projectId: encodeURIComponent(httpsMatch[1]),
      };
    }

    const sshMatch = url.match(/git@gitlab\.com:([^\/]+\/[^\/\.]+)/);
    if (sshMatch) {
      return {
        projectId: encodeURIComponent(sshMatch[1]),
      };
    }

    throw new Error(`Invalid GitLab repository URL: ${url}`);
  }

  /**
   * Check PR/MR status
   */
  async checkPRStatus(prId: string, repositoryUrl: string): Promise<PRResult> {
    if (!this.config) {
      throw new Error("PR automation service not configured");
    }

    if (this.config.provider === "github" && this.githubClient) {
      const repoInfo = this.parseGitHubUrl(repositoryUrl);
      const prNumber = parseInt(prId.replace("gh-pr-", ""), 10);

      const { data: pr } = await this.githubClient.pulls.get({
        owner: repoInfo.owner,
        repo: repoInfo.repo,
        pull_number: prNumber,
      });

      return {
        id: prId,
        status: pr.merged ? "merged" : pr.state === "closed" ? "closed" : "created",
        url: pr.html_url,
        branchName: pr.head.ref,
        title: pr.title,
        filesChanged: pr.changed_files,
      };
    } else if (this.config.provider === "gitlab" && this.gitlabClient) {
      const projectInfo = this.parseGitLabUrl(repositoryUrl);
      const mrIid = parseInt(prId.replace("gl-mr-", ""), 10);

      const mr = await this.gitlabClient.MergeRequests.show(projectInfo.projectId, mrIid);

      return {
        id: prId,
        status: mr.state === "merged" ? "merged" : mr.state === "closed" ? "closed" : "created",
        url: mr.web_url,
        branchName: mr.source_branch,
        title: mr.title,
        filesChanged: mr.changes_count || 0,
      };
    }

    throw new Error(`Unable to check PR status for provider: ${this.config.provider}`);
  }
}

export const prAutomationService = new PRAutomationService();
