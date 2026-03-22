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
  return (
    <>
      {/* Severity badge */}
      <span className={`cv-sev ${sevClass(data.sev)}`}>
        {(data.sev || "info").toUpperCase()}
      </span>

      {/* MITRE ATT&CK */}
      {data.mitre && (
        <div className="cv-pf">
          <div className="cv-pl">MITRE ATT&amp;CK</div>
          <div className="cv-pv">
            {data.mitre} &mdash; {data.technique || ""}
          </div>
        </div>
      )}

      {/* Asset Proof Grid */}
      {data.assets && data.assets.length > 0 && (
        <>
          <div className="cv-pdiv" />
          <div className="cv-pf">
            <div className="cv-pl">
              <span className="cv-pl-dot" style={{ background: "#f59e0b" }} />
              ASSET PROOF
            </div>
            <div className="cv-asset-grid">
              {data.assets.map((a, i) => (
                <AssetRow key={i} k={a.k} v={a.v} c={a.c} />
              ))}
            </div>
          </div>
        </>
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

      {/* SHA-256 evidence seal */}
      {data.hash && (
        <div className="cv-proof-hash">
          <span>SHA-256 evidence seal:</span> {data.hash}
        </div>
      )}
    </>
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
