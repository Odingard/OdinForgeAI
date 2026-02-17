import { useEffect, useRef } from "react";
import "./compare-shannon.css";

export default function CompareShannon() {
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
            Shannon finds web app bugs.
            <br />
            <span className="accent">
              OdinForge secures your
              <br />
              entire attack surface.
            </span>
          </h1>
          <p className="cp-hero-sub">
            Shannon is a capable open-source web app pentester. But modern security demands more than
            OWASP scans on a single codebase. OdinForge delivers full-spectrum AI-driven security
            across infrastructure, cloud, and network — no source code required.
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
              <span className="hl">Full</span> Stack
            </div>
            <div className="cp-stat-label">Infra &middot; Cloud &middot; Network &middot; Web Apps</div>
          </div>
          <div className="cp-stat-item">
            <div className="cp-stat-value">
              <span className="hl">0</span> Source Code
            </div>
            <div className="cp-stat-label">Black-box testing — no repo access needed</div>
          </div>
          <div className="cp-stat-item">
            <div className="cp-stat-value">
              <span className="hl">Visual</span> Graphs
            </div>
            <div className="cp-stat-label">Interactive attack path visualization</div>
          </div>
        </div>

        {/* COMPARISON TABLE */}
        <section className="cp-section cp-reveal" id="comparison">
          <div className="cp-section-label">Feature Comparison</div>
          <div className="cp-section-title">Side by side, no spin.</div>
          <p className="cp-section-desc">
            An honest look at what each tool covers. Shannon excels in a specific lane — OdinForge
            covers the full road.
          </p>

          <table className="cp-table">
            <thead>
              <tr>
                <th>Capability</th>
                <th>&#x2B21; OdinForge</th>
                <th>Shannon</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Attack Surface</td>
                <td><span className="cp-check">Web apps, infrastructure, cloud, network</span></td>
                <td><span className="cp-limited">Web applications only</span></td>
              </tr>
              <tr>
                <td>Testing Approach</td>
                <td><span className="cp-check">Black-box &amp; white-box</span></td>
                <td><span className="cp-limited">White-box only (requires source code)</span></td>
              </tr>
              <tr>
                <td>Attack Graph Visualization</td>
                <td><span className="cp-check">Interactive, animated attack paths</span></td>
                <td><span className="cp-miss">Text-based reports only</span></td>
              </tr>
              <tr>
                <td>Remediation Guidance</td>
                <td><span className="cp-check">Prioritized fixes with code-level guidance</span></td>
                <td><span className="cp-miss">Identifies vulns, no fix guidance</span></td>
              </tr>
              <tr>
                <td>AI-Driven Simulations</td>
                <td><span className="cp-check">Adaptive attack paths based on findings</span></td>
                <td><span className="cp-check">AI-guided exploitation with Claude SDK</span></td>
              </tr>
              <tr>
                <td>Exploit Validation</td>
                <td><span className="cp-check">Proof-of-exploitation with evidence chain</span></td>
                <td><span className="cp-check">"No exploit, no report" policy</span></td>
              </tr>
              <tr>
                <td>Vulnerability Coverage</td>
                <td><span className="cp-check">Full spectrum — OWASP, misconfigs, logic flaws</span></td>
                <td><span className="cp-limited">OWASP core (Injection, XSS, SSRF, Auth)</span></td>
              </tr>
              <tr>
                <td>Cloud &amp; Container Security</td>
                <td><span className="cp-check">AWS, Azure, GCP, Kubernetes, Docker</span></td>
                <td><span className="cp-miss">Not supported</span></td>
              </tr>
              <tr>
                <td>Network Pentesting</td>
                <td><span className="cp-check">Internal &amp; external network assessment</span></td>
                <td><span className="cp-miss">Not supported</span></td>
              </tr>
              <tr>
                <td>Continuous Monitoring</td>
                <td><span className="cp-check">24/7 posture monitoring &amp; drift detection</span></td>
                <td><span className="cp-limited">On-demand scans (~1.5 hrs per run)</span></td>
              </tr>
              <tr>
                <td>Evidence Collection</td>
                <td><span className="cp-check">Forensic-grade with chain of custody</span></td>
                <td><span className="cp-check">PoC screenshots &amp; payloads</span></td>
              </tr>
              <tr>
                <td>Enterprise Scale</td>
                <td><span className="cp-check">Multi-tenant, 10k+ asset environments</span></td>
                <td><span className="cp-limited">Single-app scans</span></td>
              </tr>
              <tr>
                <td>CI/CD Integration</td>
                <td><span className="cp-check">Full pipeline integration</span></td>
                <td><span className="cp-check">Docker-based CI/CD support</span></td>
              </tr>
              <tr>
                <td>Pricing Model</td>
                <td><span className="cp-check">Platform license</span></td>
                <td><span className="cp-limited">Open-source (Lite) + API costs (~$8-10/scan)</span></td>
              </tr>
            </tbody>
          </table>
        </section>

        {/* ADVANTAGES */}
        <section className="cp-section cp-reveal">
          <div className="cp-section-label">Why OdinForge</div>
          <div className="cp-section-title">Where OdinForge goes further.</div>
          <p className="cp-section-desc">
            Shannon does one thing well. OdinForge was built for the security challenges Shannon
            doesn't touch.
          </p>

          <div className="cp-advantages-grid">
            <div className="cp-adv-card">
              <div className="cp-adv-number">01</div>
              <div className="cp-adv-title">
                Your entire attack surface.
                <br />
                Not just web apps.
              </div>
              <div className="cp-adv-desc">
                Shannon only tests web applications with source code access. That leaves your
                infrastructure, cloud environments, network perimeter, and API surface completely
                untested. OdinForge maps and tests everything — from your Kubernetes clusters to your
                external network exposure.
              </div>
              <div className="cp-adv-detail">
                <span className="tag">SCOPE</span>
                <span>
                  Infra &bull; Cloud (AWS/Azure/GCP) &bull; Network &bull; APIs &bull; Web Apps — all
                  from one platform.
                </span>
              </div>
            </div>

            <div className="cp-adv-card">
              <div className="cp-adv-number">02</div>
              <div className="cp-adv-title">
                No source code?
                <br />
                No problem.
              </div>
              <div className="cp-adv-desc">
                Shannon requires access to your application's source code and repository layout.
                That's a non-starter for testing third-party apps, acquired systems, or environments
                where sharing source isn't feasible. OdinForge runs full black-box assessments against
                live targets — exactly how a real attacker would.
              </div>
              <div className="cp-adv-detail">
                <span className="tag">ACCESS</span>
                <span>
                  Black-box testing from the outside in. White-box when you want deeper coverage. Your
                  choice.
                </span>
              </div>
            </div>

            <div className="cp-adv-card">
              <div className="cp-adv-number">03</div>
              <div className="cp-adv-title">See the attack, don't just read about it.</div>
              <div className="cp-adv-desc">
                Shannon outputs text-based pentest reports. Useful for security engineers, but hard to
                communicate to leadership. OdinForge renders animated, interactive attack graphs that
                show exactly how an attacker would chain vulnerabilities across your environment — from
                initial access to full compromise.
              </div>
              <div className="cp-adv-detail">
                <span className="tag">VISUAL</span>
                <span>
                  Present attack paths to your board in minutes, not hours of report translation.
                </span>
              </div>
            </div>

            <div className="cp-adv-card">
              <div className="cp-adv-number">04</div>
              <div className="cp-adv-title">
                Don't just find problems.
                <br />
                Fix them.
              </div>
              <div className="cp-adv-desc">
                Shannon tells you what's broken with a proof-of-concept. That's valuable. But then
                what? OdinForge goes further with prioritized remediation guidance — including
                code-level fix recommendations, risk-ranked by business impact so your team knows
                exactly what to tackle first.
              </div>
              <div className="cp-adv-detail">
                <span className="tag">REMEDIATION</span>
                <span>
                  Actionable fix recommendations, not just a list of CVEs to Google.
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* SHANNON CREDIT */}
        <section className="cp-shannon-credit cp-reveal">
          <div className="cp-shannon-box">
            <div>
              <h3>Credit where it's due — Shannon is impressive.</h3>
              <p>
                We respect what the Keygraph team has built. Shannon's autonomous exploitation and "no
                exploit, no report" approach pushes the entire industry forward. If you're looking for
                a focused, open-source web app pentester, it's one of the best.
              </p>
              <p style={{ marginTop: 16 }}>
                But most security teams need more than web app testing. That's where OdinForge picks
                up.
              </p>
            </div>
            <div className="cp-shannon-list">
              <div className="cp-shannon-list-item">
                <span className="icon">{"\u2713"}</span>
                <span>
                  <strong>Shannon excels at</strong> autonomous web app exploit validation with minimal
                  false positives
                </span>
              </div>
              <div className="cp-shannon-list-item">
                <span className="icon">{"\u2713"}</span>
                <span>
                  <strong>Shannon excels at</strong> OWASP vulnerability coverage on apps with source
                  code access
                </span>
              </div>
              <div className="cp-shannon-list-item">
                <span className="icon">&rarr;</span>
                <span>
                  <strong>OdinForge adds</strong> full attack surface coverage beyond web apps
                </span>
              </div>
              <div className="cp-shannon-list-item">
                <span className="icon">&rarr;</span>
                <span>
                  <strong>OdinForge adds</strong> black-box testing, visual attack graphs, and
                  remediation
                </span>
              </div>
              <div className="cp-shannon-list-item">
                <span className="icon">&rarr;</span>
                <span>
                  <strong>OdinForge adds</strong> enterprise scale, continuous monitoring, and cloud
                  security
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="cp-cta-section" id="cta">
          <div className="cp-cta-box cp-reveal">
            <h2>Ready to see the full picture?</h2>
            <p>
              Get a live walkthrough of OdinForge against your actual environment. See what Shannon
              misses.
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
            2026. Shannon information sourced from{" "}
            <a
              href="https://github.com/KeygraphHQ/shannon"
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
