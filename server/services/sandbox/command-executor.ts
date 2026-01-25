import { EventEmitter } from "events";
import { spawn } from "child_process";

export interface CommandExecutionRequest {
  command: string;
  args?: string[];
  timeout?: number;
}

export interface CommandExecutionResult {
  success: boolean;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timing: {
    startTime: number;
    endTime: number;
    duration: number;
  };
  killed: boolean;
  signal?: string;
  error?: string;
}

export interface CommandInjectionTestResult {
  isVulnerable: boolean;
  confidenceScore: number;
  evidence: {
    payloadUsed: string;
    executionMethod: string;
    analysisType: string;
    indicators: string[];
  };
  mitreId: string;
  severity: "critical" | "high" | "medium" | "low";
}

const SAFE_VALIDATION_COMMANDS = [
  "echo",
  "whoami",
  "id",
  "hostname",
  "uname",
  "pwd",
  "date",
  "uptime",
];

const INJECTION_PATTERNS = [
  { pattern: /;/, name: "semicolon_chain", description: "Command chaining with semicolon", severity: "critical" as const },
  { pattern: /\|(?!\|)/, name: "pipe_chain", description: "Command piping", severity: "critical" as const },
  { pattern: /&&/, name: "and_chain", description: "Command chaining with AND", severity: "critical" as const },
  { pattern: /\|\|/, name: "or_chain", description: "Command chaining with OR", severity: "high" as const },
  { pattern: /`/, name: "backtick", description: "Command substitution with backticks", severity: "critical" as const },
  { pattern: /\$\(/, name: "dollar_paren", description: "Command substitution with $()", severity: "critical" as const },
  { pattern: /\$\{/, name: "brace_expand", description: "Parameter expansion", severity: "high" as const },
  { pattern: /\n|\r/, name: "newline", description: "Newline injection", severity: "critical" as const },
  { pattern: />/, name: "redirect_out", description: "Output redirection", severity: "high" as const },
  { pattern: /</, name: "redirect_in", description: "Input redirection", severity: "high" as const },
  { pattern: /\x00/, name: "null_byte", description: "Null byte injection", severity: "critical" as const },
  { pattern: /\.\.\//, name: "path_traversal", description: "Path traversal", severity: "high" as const },
  { pattern: /\$IFS/, name: "ifs_injection", description: "IFS variable injection", severity: "critical" as const },
  { pattern: /\${.*:-.*}/, name: "default_expansion", description: "Default value expansion", severity: "medium" as const },
];

const DANGEROUS_COMMANDS = [
  "rm", "dd", "mkfs", "shutdown", "reboot", "kill", "killall",
  "chmod", "chown", "sudo", "su", "mount", "umount", "fdisk",
  "wget", "curl", "nc", "netcat", "python", "perl", "ruby",
  "bash", "sh", "zsh", "csh", "ksh", "fish",
];

class CommandExecutor extends EventEmitter {
  testCommandInjection(
    targetCommand: string,
    userInput: string,
    injectionType: "argument" | "interpolation" | "environment"
  ): CommandInjectionTestResult {
    const indicators: string[] = [];
    let maxSeverity: "critical" | "high" | "medium" | "low" = "low";
    let confidenceScore = 0;

    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.pattern.test(userInput)) {
        indicators.push(`Injection pattern detected: ${pattern.description}`);
        confidenceScore += this.getSeverityScore(pattern.severity);
        
        if (this.compareSeverity(pattern.severity, maxSeverity) > 0) {
          maxSeverity = pattern.severity;
        }
      }
    }

    for (const dangerousCmd of DANGEROUS_COMMANDS) {
      const cmdPattern = new RegExp(`\\b${dangerousCmd}\\b`, 'i');
      if (cmdPattern.test(userInput)) {
        indicators.push(`Dangerous command detected: ${dangerousCmd}`);
        confidenceScore += 25;
        if (this.compareSeverity("critical", maxSeverity) > 0) {
          maxSeverity = "critical";
        }
      }
    }

    if (userInput.length > 1000) {
      indicators.push("Excessively long input (potential buffer overflow)");
      confidenceScore += 10;
    }

    const hasSpecialChars = /[^\w\s\-_.@\/]/.test(userInput);
    if (hasSpecialChars && indicators.length === 0) {
      indicators.push("Special characters present that may be interpreted by shell");
      confidenceScore += 5;
      maxSeverity = "low";
    }

    if (injectionType === "interpolation" && indicators.length > 0) {
      confidenceScore *= 1.5;
      indicators.push("Interpolation context increases exploitation likelihood");
    }

    if (injectionType === "environment") {
      const envVarPattern = /\$\w+|%\w+%/;
      if (envVarPattern.test(userInput)) {
        indicators.push("Environment variable reference detected");
        confidenceScore += 15;
      }
    }

    confidenceScore = Math.min(100, Math.round(confidenceScore));

    const isVulnerable = confidenceScore >= 60 || maxSeverity === "critical";

    console.log(`[CommandExecutor] Static analysis of "${userInput.substring(0, 50)}..." - Vulnerable: ${isVulnerable}, Confidence: ${confidenceScore}%`);

    return {
      isVulnerable,
      confidenceScore,
      evidence: {
        payloadUsed: userInput,
        executionMethod: injectionType,
        analysisType: "static_pattern_matching",
        indicators,
      },
      mitreId: "T1059",
      severity: maxSeverity,
    };
  }

  validateCommandSafety(command: string): {
    isSafe: boolean;
    reason?: string;
    sanitizedCommand?: string;
    detectedPatterns: string[];
  } {
    const detectedPatterns: string[] = [];
    
    const parts = command.split(/\s+/);
    const baseCommand = (parts[0] || "").split("/").pop() || "";

    if (!SAFE_VALIDATION_COMMANDS.includes(baseCommand)) {
      return {
        isSafe: false,
        reason: `Command "${baseCommand}" is not in the allowed list for safe validation. Allowed: ${SAFE_VALIDATION_COMMANDS.join(", ")}`,
        detectedPatterns,
      };
    }

    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.pattern.test(command)) {
        detectedPatterns.push(pattern.description);
      }
    }

    if (detectedPatterns.length > 0) {
      return {
        isSafe: false,
        reason: `Dangerous patterns detected: ${detectedPatterns.join(", ")}`,
        detectedPatterns,
      };
    }

    for (const dangerousCmd of DANGEROUS_COMMANDS) {
      if (command.includes(dangerousCmd)) {
        return {
          isSafe: false,
          reason: `Dangerous command "${dangerousCmd}" detected in input`,
          detectedPatterns: [`dangerous_command:${dangerousCmd}`],
        };
      }
    }

    return {
      isSafe: true,
      sanitizedCommand: command,
      detectedPatterns,
    };
  }

  async executeValidationCommand(
    command: string,
    expectedOutputPattern?: RegExp
  ): Promise<{
    success: boolean;
    output: string;
    matchesExpected: boolean;
    executionResult: CommandExecutionResult;
  }> {
    const safetyCheck = this.validateCommandSafety(command);
    
    if (!safetyCheck.isSafe) {
      return {
        success: false,
        output: "",
        matchesExpected: false,
        executionResult: {
          success: false,
          exitCode: null,
          stdout: "",
          stderr: safetyCheck.reason || "Command validation failed",
          timing: { startTime: 0, endTime: 0, duration: 0 },
          killed: false,
          error: safetyCheck.reason,
        },
      };
    }

    const parts = command.split(/\s+/);
    const cmd = parts[0];
    const args = parts.slice(1);

    const startTime = Date.now();
    
    return new Promise((resolve) => {
      let stdout = "";
      let stderr = "";
      let killed = false;
      
      const safeEnv = {
        PATH: "/usr/bin:/bin",
        HOME: "/tmp",
        USER: "nobody",
        LANG: "C",
      };

      const proc = spawn(cmd, args, {
        cwd: "/tmp",
        env: safeEnv,
        timeout: 5000,
        shell: false,
        uid: process.getuid?.() || undefined,
        gid: process.getgid?.() || undefined,
      });

      const timeoutHandle = setTimeout(() => {
        killed = true;
        proc.kill("SIGKILL");
      }, 5000);

      proc.stdout?.on("data", (data: Buffer) => {
        stdout += data.toString().substring(0, 10000);
      });

      proc.stderr?.on("data", (data: Buffer) => {
        stderr += data.toString().substring(0, 10000);
      });

      proc.on("close", (code: number | null, signal: string | null) => {
        clearTimeout(timeoutHandle);
        const endTime = Date.now();
        
        const output = stdout || stderr;
        const matchesExpected = expectedOutputPattern 
          ? expectedOutputPattern.test(output)
          : code === 0;

        resolve({
          success: code === 0,
          output,
          matchesExpected,
          executionResult: {
            success: code === 0,
            exitCode: code,
            stdout,
            stderr,
            timing: {
              startTime,
              endTime,
              duration: endTime - startTime,
            },
            killed,
            signal: signal || undefined,
          },
        });
      });

      proc.on("error", (error: Error) => {
        clearTimeout(timeoutHandle);
        const endTime = Date.now();

        resolve({
          success: false,
          output: "",
          matchesExpected: false,
          executionResult: {
            success: false,
            exitCode: null,
            stdout,
            stderr,
            timing: {
              startTime,
              endTime,
              duration: endTime - startTime,
            },
            killed,
            error: error.message,
          },
        });
      });
    });
  }

  sanitizeInput(input: string): string {
    let sanitized = input;

    sanitized = sanitized.replace(/[;|&`$()<>{}[\]\n\r\x00]/g, "");
    
    sanitized = sanitized.replace(/\.\.\//g, "");
    
    sanitized = sanitized.substring(0, 1000);

    return sanitized;
  }

  getSafeCommands(): string[] {
    return [...SAFE_VALIDATION_COMMANDS];
  }

  getInjectionPatterns(): { pattern: string; name: string; description: string; severity: string }[] {
    return INJECTION_PATTERNS.map(p => ({
      pattern: p.pattern.source,
      name: p.name,
      description: p.description,
      severity: p.severity,
    }));
  }

  private getSeverityScore(severity: string): number {
    switch (severity) {
      case "critical": return 35;
      case "high": return 25;
      case "medium": return 15;
      case "low": return 5;
      default: return 5;
    }
  }

  private compareSeverity(a: string, b: string): number {
    const order = { critical: 4, high: 3, medium: 2, low: 1 };
    return (order[a as keyof typeof order] || 0) - (order[b as keyof typeof order] || 0);
  }
}

export const commandExecutor = new CommandExecutor();
