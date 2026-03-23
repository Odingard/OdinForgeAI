import { useState, useCallback } from "react";

// ── Types ────────────────────────────────────────────────────────────────────

export interface AssetProofItem {
  k: string;
  v: string;
  c?: string;
}

export interface EvidenceData {
  title: string;
  sev: string;
  technique?: string;
  mitre?: string;
  assets?: AssetProofItem[];
  status?: number;
  evidence?: string;
  extracted?: string;
  curl?: string;
  ts?: string;
  hash?: string | null;
  credentialType?: string;     // e.g. "jwt", "api_key", "session_cookie"
  confidence?: string;         // e.g. "85%"
  matchedPatterns?: string[];  // Patterns that confirmed the exploit
}

interface EvidencePanelProps {
  data: EvidenceData | null;
  onClose: () => void;
}

// ── Severity → CSS class ─────────────────────────────────────────────────────

function sevClass(sev: string): string {
  switch (sev) {
    case "critical": return "sc";
    case "high":     return "sh";
    case "medium":   return "sm";
    default:         return "si";
  }
}

// ── Component ────────────────────────────────────────────────────────────────

export function EvidencePanel({ data, onClose }: EvidencePanelProps) {
  const isOpen = data !== null;

  return (
    <div className={`cv-panel${isOpen ? "" : " shut"}`}>
      <div className="cv-ph">
        <span className="cv-ph-t">{data?.title || "evidence"}</span>
        <button className="cv-ph-x" onClick={onClose}>
          {"\u2715"}
        </button>
      </div>
      <div className="cv-pb">
        {!data ? (
          <div className="cv-pe">
            click a node on the<br />
            network map to inspect<br />
            its evidence &amp; asset proof
          </div>
        ) : (
          <EvidenceContent data={data} />
        )}
      </div>
    </div>
  );
}

// ── Evidence Content ─────────────────────────────────────────────────────────

function EvidenceContent({ data }: { data: EvidenceData }) {
  // Determine whether this node has exploit-level evidence
  const hasExploitEvidence = !!(data.evidence || data.extracted || data.curl || data.status != null);

  return (
    <>
      {/* Severity + confidence badges */}
      <div style={{ display: "flex", gap: "6px", alignItems: "center", flexWrap: "wrap" }}>
        <span className={`cv-sev ${sevClass(data.sev)}`}>
          {(data.sev || "info").toUpperCase()}
        </span>
        {data.confidence && (
          <span className="cv-sev" style={{ background: "rgba(59,130,246,.15)", color: "#60a5fa" }}>
            {data.confidence} confidence
          </span>
        )}
        {data.credentialType && (
          <span className="cv-sev" style={{ background: "rgba(239,68,68,.15)", color: "#f87171" }}>
            {data.credentialType}
          </span>
        )}
      </div>

      {/* Technique (shown even without MITRE ID) */}
      {data.technique && (
        <div className="cv-pf">
          <div className="cv-pl">{data.mitre ? "MITRE ATT&CK" : "TECHNIQUE"}</div>
          <div className="cv-pv">
            {data.mitre ? `${data.mitre} \u2014 ` : ""}{data.technique}
          </div>
        </div>
      )}

      {/* Matched patterns (what proved the exploit) */}
      {data.matchedPatterns && data.matchedPatterns.length > 0 && (
        <div className="cv-pf">
          <div className="cv-pl">
            <span className="cv-pl-dot" style={{ background: "#22c55e" }} />
            MATCHED PATTERNS
          </div>
          <div className="cv-code" style={{ color: "#22c55e", borderColor: "rgba(34,197,94,.2)" }}>
            {data.matchedPatterns.join("\n")}
          </div>
        </div>
      )}

      {/* Asset Proof Grid / Node Context */}
      {data.assets && data.assets.length > 0 && (
        <>
          <div className="cv-pdiv" />
          <div className="cv-pf">
            <div className="cv-pl">
              <span className="cv-pl-dot" style={{ background: hasExploitEvidence ? "#f59e0b" : "#6b7280" }} />
              {hasExploitEvidence ? "ASSET PROOF" : "NODE CONTEXT"}
            </div>
            <div className="cv-asset-grid">
              {data.assets.map((a, i) => (
                <AssetRow key={i} k={a.k} v={a.v} c={a.c} />
              ))}
            </div>
          </div>
        </>
      )}

      {/* Informational note for nodes without exploit evidence */}
      {!hasExploitEvidence && (
        <div className="cv-pf">
          <div className="cv-pv" style={{ color: "#64748b", fontSize: "9px", fontStyle: "italic" }}>
            Discovered during surface reconnaissance.
            No exploit evidence collected yet.
          </div>
        </div>
      )}

      {/* HTTP Status */}
      {data.status != null && (
        <>
          <div className="cv-pdiv" />
          <div className="cv-pf">
            <div className="cv-pl">HTTP STATUS</div>
            <div
              className="cv-pv"
              style={{ color: data.status === 200 ? "#22c55e" : "#f59e0b" }}
            >
              {data.status} OK &mdash; confirmed live
            </div>
          </div>
        </>
      )}

      {/* Evidence snippet */}
      {data.evidence && (
        <div className="cv-pf">
          <div className="cv-pl">EVIDENCE SNIPPET</div>
          <div className="cv-code">{data.evidence}</div>
        </div>
      )}

      {/* Extracted data */}
      {data.extracted && (
        <div className="cv-pf">
          <div className="cv-pl">
            <span className="cv-pl-dot" style={{ background: "#ef4444" }} />
            EXTRACTED DATA
          </div>
          <div
            className="cv-code"
            style={{ color: "#ef4444", borderColor: "rgba(239,68,68,.2)" }}
          >
            {data.extracted}
          </div>
        </div>
      )}

      {/* Reproduce (curl / cli) */}
      {data.curl && (
        <div className="cv-pf">
          <div className="cv-pl">REPRODUCE (curl / cli)</div>
          <div className="cv-code">{data.curl}</div>
        </div>
      )}

      {/* Confirmed timestamp */}
      {data.ts && (
        <>
          <div className="cv-pdiv" />
          <div className="cv-pf">
            <div className="cv-pl">CONFIRMED AT</div>
            <div className="cv-pv" style={{ color: "#475569", fontSize: "9px" }}>
              {data.ts}
            </div>
          </div>
        </>
      )}

      {/* SHA-256 evidence seal — copyable with explanation tooltip */}
      {data.hash && (
        <HashSeal hash={data.hash} />
      )}
    </>
  );
}

// ── Hash Seal (copyable with tooltip) ────────────────────────────────────────

function HashSeal({ hash }: { hash: string }) {
  const [copied, setCopied] = useState(false);
  const [showTip, setShowTip] = useState(false);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(hash).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {
      // Fallback: select text for manual copy
    });
  }, [hash]);

  return (
    <div
      className="cv-proof-hash cv-proof-hash-interactive"
      onClick={handleCopy}
      onMouseEnter={() => setShowTip(true)}
      onMouseLeave={() => setShowTip(false)}
      title="Cryptographic proof this evidence was captured at assessment time and has not been modified. Click to copy."
      role="button"
      tabIndex={0}
      onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") handleCopy(); }}
    >
      <div className="cv-proof-hash-label">
        <span>SHA-256 evidence seal</span>
        <span className="cv-proof-hash-info" aria-label="What is this?">&#9432;</span>
      </div>
      <div className="cv-proof-hash-value">{hash}</div>
      {showTip && !copied && (
        <div className="cv-proof-hash-tooltip">
          Cryptographic proof this evidence was captured at assessment time
          and has not been modified. Click to copy.
        </div>
      )}
      {copied && (
        <div className="cv-proof-hash-tooltip cv-proof-hash-copied">
          Copied to clipboard
        </div>
      )}
    </div>
  );
}

// ── Asset Row ────────────────────────────────────────────────────────────────

function AssetRow({ k, v, c }: { k: string; v: string; c?: string }) {
  return (
    <>
      <span className="cv-ag-k">{k}</span>
      <span className={`cv-ag-v ${c || ""}`}>{v}</span>
    </>
  );
}
