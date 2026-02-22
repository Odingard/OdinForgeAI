import { useEffect, useRef } from "react";
import { BENCHMARK_RUNS, XBOW_BENCHMARK, BREACH_CHAIN_BENCHMARK } from "@/lib/benchmark-results";
import "./compare-shannon.css";

export default function BenchmarkResults() {
  const wrapperRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const els = wrapperRef.current?.querySelectorAll(".cp-reveal");
    if (!els) return;
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) entry.target.classList.add("visible");
        });
      },
      { threshold: 0.1, rootMargin: "0px 0px -40px 0px" }
    );
    els.forEach((el) => observer.observe(el));
    return () => observer.disconnect();
  }, []);

  const latest = BENCHMARK_RUNS[0];

  return (
    <div className="compare-page" ref={wrapperRef}>
      <div className="cp-grid-bg" />

      <div className="cp-wrapper">
        {/* NAV */}
        <nav className="cp-nav">
          <a href="/" className="cp-nav-logo">
            ODIN<span>FORGE</span>
          </a>
          <a href="#reproduce" className="cp-nav-cta">
            Reproduce It Yourself &rarr;
          </a>
        </nav>

        {/* HERO */}
        <section className="cp-hero">
          <div className="cp-hero-badge">
            <span className="dot" /> Benchmark Results &mdash; {latest.target} {latest.targetVersion}
          </div>
          <h1>
            Transparent. Reproducible.
            <br />
            <span className="accent">No Cherry-Picking.</span>
          </h1>
          <p className="cp-hero-sub">
            OdinForge publishes full benchmark results against real vulnerable applications &mdash;
            including misses. Our exploit agent uses a multi-turn tool-calling loop with real HTTP
            validation, not a single LLM prompt. These results are reproducible from source.
          </p>
          <div className="cp-hero-actions">
            <a href="/signup" className="cp-btn-primary">
              Start Free Trial &rarr;
            </a>
            <a href="#results" className="cp-btn-secondary">
              See Results &darr;
            </a>
          </div>
        </section>

        {/* STATS BAR */}
        <div className="cp-stats-bar">
          <div className="cp-stat-item">
            <div className="cp-stat-value">
              <span className="hl">{latest.summary.passRate}</span>
            </div>
            <div className="cp-stat-label">Scenarios Passed</div>
          </div>
          <div className="cp-stat-item">
            <div className="cp-stat-value">
              <span className="hl">{latest.summary.detectionRate}</span>
            </div>
            <div className="cp-stat-label">Detection Rate</div>
          </div>
          <div className="cp-stat-item">
            <div className="cp-stat-value">
              <span className="hl">{latest.summary.totalToolCalls}</span>
            </div>
            <div className="cp-stat-label">Tool Calls (Real HTTP)</div>
          </div>
          <div className="cp-stat-item">
            <div className="cp-stat-value">
              <span className="hl">{Math.round(latest.summary.totalTimeMs / 1000)}s</span>
            </div>
            <div className="cp-stat-label">Total Execution Time</div>
          </div>
        </div>

        {/* RESULTS TABLE */}
        <section className="cp-section cp-reveal" id="results">
          <div className="cp-section-label">Per-Scenario Breakdown</div>
          <div className="cp-section-title">
            {latest.summary.passed}/{latest.summary.total} scenarios passed against {latest.target}.
          </div>
          <p className="cp-section-desc">
            Each scenario targets a specific attack surface of {latest.target} ({latest.targetVersion}).
            The exploit agent autonomously decides which tools to invoke, which payloads to test,
            and how to chain findings &mdash; with no human guidance.
          </p>

          <table className="cp-table">
            <thead>
              <tr>
                <th>Scenario</th>
                <th>Status</th>
                <th>Expected</th>
                <th>Found</th>
                <th>Chains</th>
                <th>Tools</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {latest.scenarios.map((s) => (
                <tr key={s.id}>
                  <td>{s.name}</td>
                  <td>
                    <span className={s.status === "pass" ? "cp-check" : "cp-miss"}>
                      {s.status === "pass" ? "PASS" : "FAIL"}
                    </span>
                  </td>
                  <td>{s.expectedVulnTypes.join(", ")}</td>
                  <td>
                    {s.matchedVulnTypes.length > 0 && (
                      <span className="cp-check">{s.matchedVulnTypes.join(", ")}</span>
                    )}
                    {s.missedVulnTypes.length > 0 && (
                      <>
                        {s.matchedVulnTypes.length > 0 && <br />}
                        <span className="cp-miss">Missed: {s.missedVulnTypes.join(", ")}</span>
                      </>
                    )}
                  </td>
                  <td>
                    {s.chainsFound} found{s.validatedChains > 0 && `, ${s.validatedChains} validated`}
                  </td>
                  <td>{s.toolCalls}</td>
                  <td>{(s.timeMs / 1000).toFixed(1)}s</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        {/* METHODOLOGY */}
        <section className="cp-section cp-reveal">
          <div className="cp-section-label">Methodology</div>
          <div className="cp-section-title">How the benchmark works.</div>
          <p className="cp-section-desc">
            No cherry-picking. No curated scenarios. The agent runs autonomously against a real
            application with real vulnerabilities.
          </p>

          <div className="cp-advantages-grid">
            <div className="cp-adv-card">
              <div className="cp-adv-number">01</div>
              <div className="cp-adv-title">Real Target Application</div>
              <div className="cp-adv-desc">
                We test against OWASP Juice Shop &mdash; the most widely-used intentionally vulnerable
                web application. It contains 100+ security challenges spanning OWASP Top 10 categories.
                The Docker image is pinned to a specific version for reproducibility.
              </div>
              <div className="cp-adv-detail">
                <span className="tag">TARGET</span>
                <span>OWASP Juice Shop {latest.targetVersion} &mdash; unmodified, stock configuration</span>
              </div>
            </div>

            <div className="cp-adv-card">
              <div className="cp-adv-number">02</div>
              <div className="cp-adv-title">Agentic Tool-Calling Loop</div>
              <div className="cp-adv-desc">
                The exploit agent uses a multi-turn reasoning loop (up to {latest.environment.maxTurns} turns)
                with 6 real security tools. It decides which endpoints to probe, which payloads to test,
                and how to chain findings. Each tool fires actual HTTP requests against the target.
              </div>
              <div className="cp-adv-detail">
                <span className="tag">AGENT</span>
                <span>
                  Tools: {latest.environment.agentTools.join(", ")}
                </span>
              </div>
            </div>

            <div className="cp-adv-card">
              <div className="cp-adv-number">03</div>
              <div className="cp-adv-title">Simulation Mode</div>
              <div className="cp-adv-desc">
                Benchmarks run in <strong>simulation</strong> mode &mdash; the agent uses safe payloads
                designed for detection, not destruction. This is the same mode customers use for
                production-adjacent testing. No data is modified or exfiltrated.
              </div>
              <div className="cp-adv-detail">
                <span className="tag">MODE</span>
                <span>Simulation &mdash; safe payloads, real validation, no destructive actions</span>
              </div>
            </div>

            <div className="cp-adv-card">
              <div className="cp-adv-number">04</div>
              <div className="cp-adv-title">Validated = HTTP Evidence</div>
              <div className="cp-adv-desc">
                When we say &ldquo;validated,&rdquo; we mean the exploit agent received a confirming HTTP response.
                For SQL injection, that means a database error or auth bypass in the response body. For path
                traversal, it means file contents returned. Not speculation &mdash; proof.
              </div>
              <div className="cp-adv-detail">
                <span className="tag">EVIDENCE</span>
                <span>HTTP request/response pairs stored as chain-of-custody evidence</span>
              </div>
            </div>
          </div>
        </section>

        {/* ENVIRONMENT */}
        <section className="cp-section cp-reveal">
          <div className="cp-section-label">Test Environment</div>
          <div className="cp-section-title">Configuration details.</div>

          <table className="cp-table">
            <thead>
              <tr>
                <th>Parameter</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Target</td>
                <td>{latest.target} {latest.targetVersion}</td>
              </tr>
              <tr>
                <td>Execution Mode</td>
                <td>{latest.executionMode}</td>
              </tr>
              <tr>
                <td>Model Router</td>
                <td>{latest.environment.modelRouter}</td>
              </tr>
              <tr>
                <td>Max Agent Turns</td>
                <td>{latest.environment.maxTurns}</td>
              </tr>
              <tr>
                <td>Agent Tools</td>
                <td>{latest.environment.agentTools.length} ({latest.environment.agentTools.join(", ")})</td>
              </tr>
              <tr>
                <td>Run Date</td>
                <td>{latest.runDate}</td>
              </tr>
              <tr>
                <td>Total Execution Time</td>
                <td>{(latest.summary.totalTimeMs / 1000).toFixed(1)}s ({(latest.summary.avgTimePerScenario / 1000).toFixed(1)}s avg per scenario)</td>
              </tr>
            </tbody>
          </table>
        </section>

        {/* REPRODUCE IT */}
        <section className="cp-section cp-reveal" id="reproduce">
          <div className="cp-section-label">Reproducibility</div>
          <div className="cp-section-title">Reproduce it yourself.</div>
          <p className="cp-section-desc">
            The benchmark harness is included in the OdinForge source code. Run it against any
            OWASP Juice Shop instance to verify our results independently.
          </p>

          <div className="cp-advantages-grid">
            <div className="cp-adv-card">
              <div className="cp-adv-number">1</div>
              <div className="cp-adv-title">Start Juice Shop</div>
              <div className="cp-adv-desc">
                <code style={{ fontSize: 13, display: "block", padding: "8px 12px", background: "rgba(255,255,255,0.05)", borderRadius: 6, whiteSpace: "pre" }}>
                  docker run -d -p 3001:3000 bkimminich/juice-shop:{latest.targetVersion.replace("v", "")}
                </code>
              </div>
            </div>

            <div className="cp-adv-card">
              <div className="cp-adv-number">2</div>
              <div className="cp-adv-title">Run Benchmark</div>
              <div className="cp-adv-desc">
                <code style={{ fontSize: 13, display: "block", padding: "8px 12px", background: "rgba(255,255,255,0.05)", borderRadius: 6, whiteSpace: "pre" }}>
                  npx tsx server/benchmark/exploit-benchmark.ts \{"\n"}  http://localhost:3001 simulation
                </code>
              </div>
            </div>

            <div className="cp-adv-card">
              <div className="cp-adv-number">3</div>
              <div className="cp-adv-title">Compare Results</div>
              <div className="cp-adv-desc">
                The harness outputs a full JSON report with per-scenario results, tool call logs,
                and exploit chain details. Compare your run against our published results.
              </div>
            </div>
          </div>
        </section>

        {/* WHAT WE MISSED */}
        <section className="cp-shannon-credit cp-reveal">
          <div className="cp-shannon-box">
            <div>
              <h3>What we missed &mdash; and why we publish it.</h3>
              <p>
                Our detection rate is {latest.summary.detectionRate}, not 100%. In the API surface scenario,
                the agent missed path traversal. In several scenarios, XSS was detected via
                misconfiguration analysis rather than active exploitation. We publish these gaps because
                transparency builds more trust than a perfect score ever could.
              </p>
              <p style={{ marginTop: 16 }}>
                Every benchmark run drives improvements to our payload libraries, validation engines,
                and agent reasoning. This is a living benchmark &mdash; scores will change as the
                agent gets smarter.
              </p>
            </div>
            <div className="cp-shannon-list">
              <div className="cp-shannon-list-item">
                <span className="icon">{"\u2713"}</span>
                <span>
                  <strong>{latest.summary.totalMatched}/{latest.summary.totalExpected}</strong> expected vulnerability types detected
                </span>
              </div>
              <div className="cp-shannon-list-item">
                <span className="icon">{"\u2713"}</span>
                <span>
                  <strong>{latest.summary.validatedChains}/{latest.summary.totalChains}</strong> exploit chains backed by HTTP evidence
                </span>
              </div>
              <div className="cp-shannon-list-item">
                <span className="icon">&rarr;</span>
                <span>
                  <strong>Full JSON reports</strong> including tool call logs and timing data
                </span>
              </div>
              <div className="cp-shannon-list-item">
                <span className="icon">&rarr;</span>
                <span>
                  <strong>Open benchmark harness</strong> &mdash; run it yourself, verify independently
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* XBOW CTF BENCHMARK */}
        <section className="cp-section cp-reveal">
          <div className="cp-section-label">XBOW CTF Benchmark ({XBOW_BENCHMARK.challengesRun}/{XBOW_BENCHMARK.challengesTotal} challenges)</div>
          <div className="cp-section-title">
            {XBOW_BENCHMARK.solveRate} flags extracted &mdash; {XBOW_BENCHMARK.vulnDetectionRate} vulns detected.
          </div>
          <p className="cp-section-desc">
            The XBOW benchmark contains 104 deliberately vulnerable web applications used by
            Shannon and XBOW to measure AI pentesting capability. OdinForge runs these in
            <strong> black-box mode</strong> &mdash; no source code access. Shannon&rsquo;s 96.15% was
            achieved with full source code (white-box).
          </p>

          {XBOW_BENCHMARK.status === "preliminary" && (
            <div className="cp-shannon-box" style={{ marginBottom: 24, padding: "16px 20px" }}>
              <p style={{ margin: 0, fontSize: 14 }}>
                <strong>Preliminary results ({XBOW_BENCHMARK.challengesRun} of {XBOW_BENCHMARK.challengesTotal} challenges).</strong>{" "}
                {XBOW_BENCHMARK.note}
              </p>
            </div>
          )}

          <table className="cp-table">
            <thead>
              <tr>
                <th>Agent</th>
                <th>Mode</th>
                <th>Solve Rate</th>
                <th>Vuln Detection</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>OdinForge</strong></td>
                <td>Black-box (no source)</td>
                <td>{XBOW_BENCHMARK.solveRate}</td>
                <td><span style={{ color: "var(--yellow, #f0c040)" }}>{XBOW_BENCHMARK.vulnDetectionRate}</span></td>
              </tr>
              <tr>
                <td>Shannon Lite</td>
                <td>White-box (full source)</td>
                <td>{XBOW_BENCHMARK.shannonRate}</td>
                <td>&mdash;</td>
              </tr>
              <tr>
                <td>XBOW (official)</td>
                <td>Black-box</td>
                <td>{XBOW_BENCHMARK.xbowRate}</td>
                <td>&mdash;</td>
              </tr>
            </tbody>
          </table>

          <p className="cp-section-desc" style={{ marginTop: 24, fontSize: 14, opacity: 0.7 }}>
            Shannon reads source code to find vulnerabilities. OdinForge finds them the way an
            attacker would &mdash; from the outside. The agent detected vulns in 60% of challenges
            but needs deeper exploitation to extract flags. Nightly CI runs all 104 challenges.
          </p>
        </section>

        {/* BREACH CHAIN BENCHMARK */}
        <section className="cp-section cp-reveal">
          <div className="cp-section-label">AEV Breach Chain Benchmark</div>
          <div className="cp-section-title">
            {BREACH_CHAIN_BENCHMARK.status === "pending"
              ? "Multi-phase attack chains. Results incoming."
              : `${BREACH_CHAIN_BENCHMARK.scenariosSucceeded}/${BREACH_CHAIN_BENCHMARK.scenariosRun} chains completed — avg score ${BREACH_CHAIN_BENCHMARK.avgCompositeScore}/100`}
          </div>
          <p className="cp-section-desc">
            Finding a single vulnerability is step one. OdinForge chains exploits across multiple phases:
            SQLi &rarr; credential extraction &rarr; privilege escalation &rarr; lateral movement.
            This benchmark measures chain depth, confidence, and evidence quality &mdash; capabilities
            neither Shannon nor XBOW can match.
          </p>

          {/* Per-scenario results */}
          {BREACH_CHAIN_BENCHMARK.status === "complete" && BREACH_CHAIN_BENCHMARK.scenarios.length > 0 && (
            <table className="cp-table" style={{ marginBottom: 32 }}>
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Scenario</th>
                  <th>Status</th>
                  <th>Steps</th>
                  <th>Score</th>
                  <th>Confidence</th>
                </tr>
              </thead>
              <tbody>
                {BREACH_CHAIN_BENCHMARK.scenarios.map((s) => (
                  <tr key={s.id}>
                    <td>{s.id.startsWith("js-") ? "Juice Shop" : s.id.startsWith("dvwa-") ? "DVWA" : "WebGoat"}</td>
                    <td>{s.name}</td>
                    <td>
                      <span className={s.status === "completed" || s.compositeScore >= 40 ? "cp-check" : "cp-miss"}>
                        {s.status.toUpperCase()}
                      </span>
                    </td>
                    <td>{s.stepsSucceeded}/{s.stepsExecuted}</td>
                    <td>{s.compositeScore}/100</td>
                    <td>{s.confidence}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {/* Competitor capability matrix */}
          <div className="cp-section-label" style={{ marginTop: 16 }}>Capability Matrix</div>
          <table className="cp-table">
            <thead>
              <tr>
                <th>Capability</th>
                <th>OdinForge</th>
                <th>Shannon</th>
                <th>XBOW</th>
              </tr>
            </thead>
            <tbody>
              {BREACH_CHAIN_BENCHMARK.competitorCapability.map((row) => (
                <tr key={row.capability}>
                  <td>{row.capability}</td>
                  <td>
                    <span className={row.odinforge === "yes" ? "cp-check" : row.odinforge === "partial" ? "" : "cp-miss"}>
                      {row.odinforge === "yes" ? "\u2713" : row.odinforge === "partial" ? "Partial" : "\u2717"}
                    </span>
                  </td>
                  <td>
                    <span className={row.shannon === "yes" ? "cp-check" : row.shannon === "partial" ? "" : "cp-miss"}>
                      {row.shannon === "yes" ? "\u2713" : row.shannon === "partial" ? "Partial" : "\u2717"}
                    </span>
                  </td>
                  <td>
                    <span className={row.xbow === "yes" ? "cp-check" : row.xbow === "partial" ? "" : "cp-miss"}>
                      {row.xbow === "yes" ? "\u2713" : row.xbow === "partial" ? "Partial" : "\u2717"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <p className="cp-section-desc" style={{ marginTop: 24, fontSize: 14, opacity: 0.7 }}>
            Shannon finds vulnerabilities. XBOW validates them. OdinForge proves breaches &mdash;
            with multi-phase chains, credential harvesting, and cross-domain escalation.
            Scores improve with each iteration as step handlers are refined.
          </p>
        </section>

        {/* CTA */}
        <section className="cp-cta-section" id="cta">
          <div className="cp-cta-box cp-reveal">
            <h2>See what OdinForge finds in your environment.</h2>
            <p>
              The same agentic exploit engine that achieved {latest.summary.passRate} on Juice Shop,
              pointed at your attack surface. Start a free trial &mdash; no credit card required.
            </p>
            <div className="cp-cta-actions">
              <a href="/signup" className="cp-btn-primary">
                Start Free Trial &rarr;
              </a>
              <a href="/compare/shannon" className="cp-btn-secondary">
                Compare Platforms
              </a>
            </div>
          </div>
        </section>

        {/* FOOTER */}
        <footer className="cp-footer">
          <p>
            &copy; {new Date().getFullYear()} OdinForge. Benchmark data from {latest.runDate} against{" "}
            {latest.target} {latest.targetVersion} in {latest.executionMode} mode.
            Full methodology and source code available in the{" "}
            <a
              href="https://github.com/OdinGard/OdinForgeAI"
              target="_blank"
              rel="noopener noreferrer"
            >
              project repository
            </a>.
          </p>
        </footer>
      </div>
    </div>
  );
}
