import { useState, useRef, useEffect } from "react";
import { cn } from "@/lib/utils";
import { ChevronRight, Terminal as TerminalIcon } from "lucide-react";

interface TerminalLine {
  type: "input" | "output" | "error" | "success";
  content: string;
  timestamp?: string;
}

interface TerminalProps {
  className?: string;
  prompt?: string;
  onCommand?: (command: string) => void | Promise<string>;
  initialLines?: TerminalLine[];
  maxLines?: number;
  autoFocus?: boolean;
}

export function Terminal({
  className,
  prompt = "odin@forge:~$",
  onCommand,
  initialLines = [],
  maxLines = 100,
  autoFocus = true
}: TerminalProps) {
  const [lines, setLines] = useState<TerminalLine[]>(initialLines);
  const [input, setInput] = useState("");
  const [isProcessing, setIsProcessing] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (autoFocus && inputRef.current) {
      inputRef.current.focus();
    }
  }, [autoFocus]);

  useEffect(() => {
    // Auto-scroll to bottom
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [lines]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isProcessing) return;

    const command = input.trim();
    setInput("");

    // Add command to history
    const newLines: TerminalLine[] = [
      ...lines,
      {
        type: "input",
        content: command,
        timestamp: new Date().toISOString(),
      },
    ];

    if (onCommand) {
      setIsProcessing(true);
      try {
        const response = await onCommand(command);
        if (response) {
          newLines.push({
            type: "output",
            content: response,
            timestamp: new Date().toISOString(),
          });
        }
      } catch (error) {
        newLines.push({
          type: "error",
          content: error instanceof Error ? error.message : "Command failed",
          timestamp: new Date().toISOString(),
        });
      } finally {
        setIsProcessing(false);
      }
    }

    // Trim to max lines
    if (newLines.length > maxLines) {
      newLines.splice(0, newLines.length - maxLines);
    }

    setLines(newLines);
  };

  const getLineColor = (type: TerminalLine["type"]) => {
    switch (type) {
      case "input":
        return "text-cyan-400";
      case "error":
        return "text-red-400";
      case "success":
        return "text-green-400";
      default:
        return "text-muted-foreground";
    }
  };

  return (
    <div
      className={cn(
        "glass border border-border/50 rounded-lg overflow-hidden scan-line glow-cyan-sm",
        className
      )}
    >
      {/* Terminal header */}
      <div className="flex items-center gap-2 px-4 py-2 border-b border-border/50 bg-muted/20">
        <TerminalIcon className="h-4 w-4 text-cyan-400" />
        <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider">
          OdinForge Terminal
        </span>
        <div className="ml-auto flex gap-1.5">
          <div className="h-3 w-3 rounded-full bg-red-500/50 border border-red-500" />
          <div className="h-3 w-3 rounded-full bg-amber-500/50 border border-amber-500" />
          <div className="h-3 w-3 rounded-full bg-green-500/50 border border-green-500" />
        </div>
      </div>

      {/* Terminal content */}
      <div
        ref={containerRef}
        className="h-[400px] overflow-y-auto p-4 font-mono text-sm space-y-1 bg-black/20"
        onClick={() => inputRef.current?.focus()}
      >
        {lines.map((line, index) => (
          <div key={index} className={cn("flex gap-2", getLineColor(line.type))}>
            {line.type === "input" && (
              <span className="text-green-400 select-none">{prompt}</span>
            )}
            <span className="flex-1 break-words">{line.content}</span>
          </div>
        ))}

        {/* Input line */}
        <form onSubmit={handleSubmit} className="flex gap-2 items-center">
          <span className="text-green-400 select-none">{prompt}</span>
          <input
            ref={inputRef}
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={isProcessing}
            className="flex-1 bg-transparent border-none outline-none text-cyan-400 font-mono placeholder:text-muted-foreground/30"
            placeholder={isProcessing ? "Processing..." : "Type command..."}
            autoComplete="off"
            spellCheck={false}
          />
          <ChevronRight className={cn(
            "h-4 w-4 text-cyan-400",
            isProcessing && "animate-pulse"
          )} />
        </form>
      </div>
    </div>
  );
}

interface TerminalOutputProps {
  lines: string[];
  className?: string;
  title?: string;
}

export function TerminalOutput({ lines, className, title }: TerminalOutputProps) {
  return (
    <div className={cn("glass border border-border/50 rounded-lg overflow-hidden", className)}>
      {title && (
        <div className="flex items-center gap-2 px-4 py-2 border-b border-border/50 bg-muted/20">
          <TerminalIcon className="h-4 w-4 text-cyan-400" />
          <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider">
            {title}
          </span>
        </div>
      )}
      <div className="p-4 font-mono text-sm space-y-1 bg-black/20 max-h-[300px] overflow-y-auto">
        {lines.map((line, index) => (
          <div key={index} className="text-muted-foreground">
            {line}
          </div>
        ))}
      </div>
    </div>
  );
}

export function TerminalCommand({
  command,
  output,
  className
}: {
  command: string;
  output?: string;
  className?: string;
}) {
  return (
    <div className={cn("glass border border-border/50 rounded-lg p-4 font-mono text-sm", className)}>
      <div className="flex items-center gap-2 text-green-400 mb-2">
        <ChevronRight className="h-4 w-4" />
        <span className="text-cyan-400">{command}</span>
      </div>
      {output && (
        <div className="pl-6 text-muted-foreground whitespace-pre-wrap">
          {output}
        </div>
      )}
    </div>
  );
}
