import { useEffect, useRef } from "react";
import "./compare-shannon.css";

export default function CompareXBOW() {
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

  return (
    <div className="compare-page" ref={wrapperRef}>
      <div className="cp-grid-bg" />

      <div className="cp-wrapper">
        {/* NAV */}
        <nav className="cp-nav">
          <a href="/" className="cp-nav-logo">
            ODIN<span>FORGE</span>
          </a>
          <a href="#cta" className="cp-nav-cta">
            Request Demo &rarr;
          </a>
        </nav>

        {/* HERO */}
        <section className="cp-hero">
          <div className="cp-hero-badge">
            <span className="dot" /> Comparison Guide — Updated February 2026
          </div>
          <h1>
            XBOW finds zero-days.
            <br />
            <span className="accent">
              OdinForge chains them into
              <br />
              full breach paths.
            </span>
          </h1>
          <p className="cp-hero-sub">
            XBOW is the highest-earning AI hacker on HackerOne, backed by $117M in funding and alloy
            agent architecture. OdinForge uses alloy agents too — plus breach chain orchestration,
            cloud lateral movement, and transparent public benchmarks.
          </p>
          <div className="cp-hero-actions">
            <a href="#cta" className="cp-btn-primary">
              See OdinForge in Action &rarr;
            </a>
            <a href="#comparison" className="cp-btn-secondary">
              Jump to Comparison &darr;
            </a>
          </div>
        </section>

        {/* STATS BAR */}
        <div className="cp-stats-bar">
          <div className="cp-stat-item">
            <div className="cp-stat-value">
              <span className="hl">5/5</span> Pass
            </div>
            <div className="cp-stat-label">Benchmark scenarios &middot; Public results</div>
          </div>
          <div className="cp-stat-item">
            <div className="cp-stat-value">
              <span className="hl">Alloy</span> Agents
            </div>
            <div className="cp-stat-label">Multi-model orchestration &middot; Like XBOW</div>
          </div>
          <div className="cp-stat-item">
            <div className="cp-stat-value">
              <span className="hl">Breach</span> Chains
            </div>
            <div className="cp-stat-label">Full attack path &middot; Not just single vulns</div>
          </div>
        </div>

        {/* COMPARISON TABLE */}
        <section className="cp-section cp-reveal" id="comparison">
          <div className="cp-section-label">Feature Comparison</div>
          <div className="cp-section-title">Side by side, no spin.</div>
          <p className="cp-section-desc">
            An honest comparison of two AI-powered offensive security platforms. XBOW leads bug
            bounties — OdinForge leads enterprise security operations.
          </p>

          <table className="cp-table">
            <thead>
              <tr>
                <th>Capability</th>
                <th>&#x2B21; OdinForge</th>
                <th>XBOW</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Alloy Agent Architecture</td>
                <td><span className="cp-check">Multi-model routing (OpenAI, OpenRouter, custom)</span></td>
                <td><span className="cp-check">Alloy agents, multi-model orchestration</span></td>
              </tr>
              <tr>
                <td>Breach Chain Orchestration</td>
                <td><span className="cp-check">Multi-step chains linking vulns to full compromise</span></td>
                <td><span className="cp-miss">Single vulnerability discovery focus</span></td>
              </tr>
              <tr>
                <td>Cloud &amp; Kubernetes</td>
                <td><span className="cp-check">AWS, Azure, GCP, K8s lateral movement</span></td>
                <td><span className="cp-miss">Web application scope only</span></td>
              </tr>
              <tr>
                <td>EPSS / CVSS Scoring</td>
                <td><span className="cp-check">Deterministic EPSS + CVSS + KEV scoring engine</span></td>
                <td><span className="cp-limited">CVSS only (no EPSS integration)</span></td>
              </tr>
              <tr>
                <td>Public Benchmarks</td>
                <td><span className="cp-check">Open CI, reproducible, multi-target results</span></td>
                <td><span className="cp-miss">No published benchmark methodology</span></td>
              </tr>
              <tr>
                <td>Multi-Tenancy</td>
                <td><span className="cp-check">Row-level security, org isolation, RBAC</span></td>
                <td><span className="cp-limited">Managed service model</span></td>
              </tr>
              <tr>
                <td>Visual Attack Graphs</td>
                <td><span className="cp-check">Interactive, animated breach path visualization</span></td>
                <td><span className="cp-miss">Text-based vulnerability reports</span></td>
              </tr>
              <tr>
                <td>Zero-Day Discovery</td>
                <td><span className="cp-check">AI-driven fuzzing &amp; exploit validation</span></td>
                <td><span className="cp-check">HackerOne #1 — proven zero-day track record</span></td>
              </tr>
              <tr>
                <td>Network Pentesting</td>
                <td><span className="cp-check">Internal &amp; external network assessment</span></td>
                <td><span className="cp-miss">Not supported</span></td>
              </tr>
              <tr>
                <td>Enterprise Governance</td>
                <td><span className="cp-check">67 permissions, 8 roles, audit logging</span></td>
                <td><span className="cp-limited">Limited — managed service</span></td>
              </tr>
              <tr>
                <td>Continuous Monitoring</td>
                <td><span className="cp-check">24/7 posture monitoring &amp; drift detection</span></td>
                <td><span className="cp-limited">On-demand scanning</span></td>
              </tr>
              <tr>
                <td>Self-Hosted Option</td>
                <td><span className="cp-check">SaaS or self-hosted enterprise deployment</span></td>
                <td><span className="cp-miss">Managed service only</span></td>
              </tr>
              <tr>
                <td>Pricing Transparency</td>
                <td><span className="cp-check">Published tiers, $5K–$30K/yr range</span></td>
                <td><span className="cp-miss">Undisclosed ($117M VC-backed)</span></td>
              </tr>
            </tbody>
          </table>
        </section>

        {/* ADVANTAGES */}
        <section className="cp-section cp-reveal">
          <div className="cp-section-label">Why OdinForge</div>
          <div className="cp-section-title">Where OdinForge goes further.</div>
          <p className="cp-section-desc">
            XBOW proves alloy agents work. OdinForge proves they can do more than find single bugs.
          </p>

          <div className="cp-advantages-grid">
            <div className="cp-adv-card">
              <div className="cp-adv-number">01</div>
              <div className="cp-adv-title">
                Alloy agents are table stakes.
                <br />
                Breach chains are the edge.
              </div>
              <div className="cp-adv-desc">
                Both platforms use multi-model agent architectures. The difference is what happens
                after a vulnerability is found. XBOW reports it. OdinForge chains it — linking an
                initial foothold through lateral movement, privilege escalation, and data exfiltration
                into a complete breach narrative.
              </div>
              <div className="cp-adv-detail">
                <span className="tag">CHAINS</span>
                <span>
                  Single vulns become full breach paths — from initial access to business impact.
                </span>
              </div>
            </div>

            <div className="cp-adv-card">
              <div className="cp-adv-number">02</div>
              <div className="cp-adv-title">
                Beyond web apps.
                <br />
                Into infrastructure.
              </div>
              <div className="cp-adv-desc">
                XBOW excels at finding web application zero-days. But most breaches don't stop at the
                web tier. OdinForge tests across cloud environments (AWS, Azure, GCP), Kubernetes
                clusters, internal networks, and API surfaces — mapping the full attack surface an
                adversary would target.
              </div>
              <div className="cp-adv-detail">
                <span className="tag">SCOPE</span>
                <span>
                  Cloud &bull; K8s &bull; Network &bull; APIs &bull; Web — one platform, full
                  coverage.
                </span>
              </div>
            </div>

            <div className="cp-adv-card">
              <div className="cp-adv-number">03</div>
              <div className="cp-adv-title">
                Transparent benchmarks.
                <br />
                Not just claims.
              </div>
              <div className="cp-adv-desc">
                XBOW's results are impressive but unverifiable — no public methodology, no
                reproducible benchmarks. OdinForge publishes every benchmark run in CI with
                open methodology, threshold gating, and reproducible results against OWASP targets.
                Anyone can verify our claims.
              </div>
              <div className="cp-adv-detail">
                <span className="tag">PROOF</span>
                <span>
                  Open CI pipeline &bull; Multi-target benchmarks &bull; Public results page.
                </span>
              </div>
            </div>

            <div className="cp-adv-card">
              <div className="cp-adv-number">04</div>
              <div className="cp-adv-title">
                Enterprise-ready.
                <br />
                Not VC-dependent.
              </div>
              <div className="cp-adv-desc">
                XBOW has raised $117M — impressive, but that means enterprise pricing to match. OdinForge
                offers transparent pricing in the $5K–$30K/yr range that fills the gap between free
                OSS tools and $120K+ enterprise platforms. Plus self-hosted deployment for teams that
                need data sovereignty.
              </div>
              <div className="cp-adv-detail">
                <span className="tag">PRICING</span>
                <span>
                  SaaS or self-hosted &bull; Transparent tiers &bull; No VC premium.
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* BENCHMARK PROOF */}
        <section className="cp-section cp-reveal">
          <div className="cp-section-label">Benchmark Results</div>
          <div className="cp-section-title">Proven performance. Transparent results.</div>
          <p className="cp-section-desc">
            OdinForge publishes full benchmark results against OWASP Juice Shop &mdash; no cherry-picking.
            5/5 scenarios passed with 90% detection rate. Our exploit agent uses real HTTP validation,
            not AI speculation.
          </p>
          <div className="cp-hero-actions" style={{ justifyContent: "flex-start" }}>
            <a href="/benchmark" className="cp-btn-secondary">
              See Full Benchmark Results &rarr;
            </a>
          </div>
        </section>

        {/* XBOW CREDIT */}
        <section className="cp-shannon-credit cp-reveal">
          <div className="cp-shannon-box">
            <div>
              <h3>Credit where it's due — XBOW is formidable.</h3>
              <p>
                XBOW is the #1 ranked AI hacker on HackerOne, backed by $117M in funding from top
                investors. Their alloy agent architecture and zero-day discovery track record is
                genuinely impressive and pushes the entire AI security industry forward.
              </p>
              <p style={{ marginTop: 16 }}>
                But enterprise security needs more than bug bounty wins. That's where OdinForge picks
                up.
              </p>
            </div>
            <div className="cp-shannon-list">
              <div className="cp-shannon-list-item">
                <span className="icon">{"\u2713"}</span>
                <span>
                  <strong>XBOW excels at</strong> autonomous zero-day discovery and HackerOne bug
                  bounties
                </span>
              </div>
              <div className="cp-shannon-list-item">
                <span className="icon">{"\u2713"}</span>
                <span>
                  <strong>XBOW excels at</strong> alloy agent orchestration with proven multi-model
                  coordination
                </span>
              </div>
              <div className="cp-shannon-list-item">
                <span className="icon">&rarr;</span>
                <span>
                  <strong>OdinForge adds</strong> breach chain orchestration connecting vulns to full
                  compromise paths
                </span>
              </div>
              <div className="cp-shannon-list-item">
                <span className="icon">&rarr;</span>
                <span>
                  <strong>OdinForge adds</strong> cloud, Kubernetes, and network lateral movement
                  testing
                </span>
              </div>
              <div className="cp-shannon-list-item">
                <span className="icon">&rarr;</span>
                <span>
                  <strong>OdinForge adds</strong> transparent benchmarks, enterprise governance, and
                  self-hosted deployment
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="cp-cta-section" id="cta">
          <div className="cp-cta-box cp-reveal">
            <h2>Ready to go beyond bug bounties?</h2>
            <p>
              Get a live walkthrough of OdinForge against your actual environment. See what single-vuln
              scanners miss.
            </p>
            <div className="cp-cta-actions">
              <a href="/signup" className="cp-btn-primary">
                Request a Demo &rarr;
              </a>
              <a href="/signup" className="cp-btn-secondary">
                Talk to an Engineer
              </a>
            </div>
          </div>
        </section>

        {/* FOOTER */}
        <footer className="cp-footer">
          <p>
            &copy; {new Date().getFullYear()} OdinForge. Comparison data accurate as of February
            2026. XBOW information sourced from{" "}
            <a
              href="https://xbow.com"
              target="_blank"
              rel="noopener noreferrer"
            >
              public documentation
            </a>
            .
          </p>
        </footer>
      </div>
    </div>
  );
}
