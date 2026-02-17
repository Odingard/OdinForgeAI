import { useEffect, useRef } from "react";
import "./compare-shannon.css";

export default function CompareNodeZero() {
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
            Start Free Trial &rarr;
          </a>
        </nav>

        {/* HERO */}
        <section className="cp-hero">
          <div className="cp-hero-badge">
            <span className="dot" /> Comparison Guide — Updated February 2026
          </div>
          <h1>
            NodeZero targets enterprises.
            <br />
            <span className="accent">
              OdinForge is built
              <br />
              for every security team.
            </span>
          </h1>
          <p className="cp-hero-sub">
            Horizon3.ai's NodeZero is an autonomous pentesting platform with a strong military
            pedigree and Fortune 10 customer base. But opaque pricing, immature web app testing,
            and enterprise-only positioning leave a gap for the rest of the market. OdinForge
            fills it.
          </p>
          <div className="cp-hero-actions">
            <a href="/signup" className="cp-btn-primary">
              Start Your Free Trial &rarr;
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
            <div className="cp-stat-label">Infra &middot; Cloud &middot; Network &middot; Web &middot; API</div>
          </div>
          <div className="cp-stat-item">
            <div className="cp-stat-value">
              <span className="hl">Visual</span> Chains
            </div>
            <div className="cp-stat-label">Interactive breach chain attack paths</div>
          </div>
          <div className="cp-stat-item">
            <div className="cp-stat-value">
              <span className="hl">Open</span> Pricing
            </div>
            <div className="cp-stat-label">Transparent tiers &middot; No sales call required</div>
          </div>
        </div>

        {/* COMPARISON TABLE */}
        <section className="cp-section cp-reveal" id="comparison">
          <div className="cp-section-label">Feature Comparison</div>
          <div className="cp-section-title">OdinForge vs NodeZero — no spin.</div>
          <p className="cp-section-desc">
            Both platforms perform autonomous security validation. Here's where they differ in
            capabilities, accessibility, and approach.
          </p>

          <table className="cp-table">
            <thead>
              <tr>
                <th>Capability</th>
                <th>&#x2B21; OdinForge</th>
                <th>NodeZero</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Pricing Transparency</td>
                <td><span className="cp-check">Published pricing tiers</span></td>
                <td><span className="cp-miss">Custom quotes only, opaque</span></td>
              </tr>
              <tr>
                <td>Internal Pentesting</td>
                <td><span className="cp-check">Full network traversal &amp; exploitation</span></td>
                <td><span className="cp-check">Autonomous network pentesting (core strength)</span></td>
              </tr>
              <tr>
                <td>External Pentesting</td>
                <td><span className="cp-check">External recon &amp; exploitation</span></td>
                <td><span className="cp-check">External attack surface testing</span></td>
              </tr>
              <tr>
                <td>Web Application Testing</td>
                <td><span className="cp-check">Full web app assessment</span></td>
                <td><span className="cp-limited">Early Access — not yet mature</span></td>
              </tr>
              <tr>
                <td>Cloud Security</td>
                <td><span className="cp-check">AWS, Azure, GCP, Kubernetes</span></td>
                <td><span className="cp-check">Hybrid cloud/on-prem attack paths</span></td>
              </tr>
              <tr>
                <td>Active Directory</td>
                <td><span className="cp-check">AD exploitation &amp; lateral movement</span></td>
                <td><span className="cp-check">First AI to solve GOAD benchmark</span></td>
              </tr>
              <tr>
                <td>Breach Chain Visualization</td>
                <td><span className="cp-check">Interactive animated attack graphs</span></td>
                <td><span className="cp-limited">Attack path view (less visual)</span></td>
              </tr>
              <tr>
                <td>Remediation Guidance</td>
                <td><span className="cp-check">Prioritized code-level fix recommendations</span></td>
                <td><span className="cp-limited">One-click retest, limited fix guidance</span></td>
              </tr>
              <tr>
                <td>Reporting</td>
                <td><span className="cp-check">Executive + technical reports</span></td>
                <td><span className="cp-limited">Weak for large enterprises per reviews</span></td>
              </tr>
              <tr>
                <td>OT/ICS Safety</td>
                <td><span className="cp-check">Safe scanning with configurable intensity</span></td>
                <td><span className="cp-miss">Can restart older PLCs/lock up ICS systems</span></td>
              </tr>
              <tr>
                <td>Multi-Tenant</td>
                <td><span className="cp-check">Native multi-org with RLS isolation</span></td>
                <td><span className="cp-limited">MSSP support via partner program</span></td>
              </tr>
              <tr>
                <td>Deployment</td>
                <td><span className="cp-check">SaaS — no agents, no containers</span></td>
                <td><span className="cp-limited">Docker container deployment</span></td>
              </tr>
              <tr>
                <td>Continuous Testing</td>
                <td><span className="cp-check">24/7 monitoring with drift detection</span></td>
                <td><span className="cp-check">Unlimited on-demand pentests</span></td>
              </tr>
              <tr>
                <td>Phishing Simulation</td>
                <td><span className="cp-check">Full phishing campaign simulation</span></td>
                <td><span className="cp-limited">Phishing impact only (no templates)</span></td>
              </tr>
            </tbody>
          </table>
        </section>

        {/* ADVANTAGES */}
        <section className="cp-section cp-reveal">
          <div className="cp-section-label">Why OdinForge</div>
          <div className="cp-section-title">Where OdinForge goes further.</div>
          <p className="cp-section-desc">
            NodeZero is powerful for enterprises with dedicated security teams. OdinForge brings
            that same validation capability to everyone else.
          </p>

          <div className="cp-advantages-grid">
            <div className="cp-adv-card">
              <div className="cp-adv-number">01</div>
              <div className="cp-adv-title">
                Transparent pricing.
                <br />
                No sales call required.
              </div>
              <div className="cp-adv-desc">
                NodeZero requires contacting sales for a custom quote — a process that can take
                weeks and often reveals pricing that only works for large enterprises. OdinForge
                publishes clear pricing tiers so you know exactly what you're getting before you
                sign up.
              </div>
              <div className="cp-adv-detail">
                <span className="tag">PRICING</span>
                <span>
                  See the price. Start the trial. No procurement dance.
                </span>
              </div>
            </div>

            <div className="cp-adv-card">
              <div className="cp-adv-number">02</div>
              <div className="cp-adv-title">
                Full web app testing.
                <br />
                Not "Early Access."
              </div>
              <div className="cp-adv-desc">
                NodeZero's web application testing is still in Early Access — limited in scope
                compared to dedicated DAST tools. OdinForge includes full web application
                assessment out of the box: OWASP Top 10, auth flaws, business logic testing, and
                API security — all production-ready from day one.
              </div>
              <div className="cp-adv-detail">
                <span className="tag">WEB APPS</span>
                <span>
                  Production-grade web app testing, not a beta feature.
                </span>
              </div>
            </div>

            <div className="cp-adv-card">
              <div className="cp-adv-number">03</div>
              <div className="cp-adv-title">
                Visual breach chains
                <br />
                your board can understand.
              </div>
              <div className="cp-adv-desc">
                NodeZero's reporting is frequently criticized in reviews as "ineffective" for
                large enterprises. OdinForge renders interactive, animated breach chain
                visualizations that make attack paths immediately clear to both technical teams
                and executive leadership — no translation required.
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
                Safe for every
                <br />
                environment.
              </div>
              <div className="cp-adv-desc">
                Multiple NodeZero reviewers report that scans can restart older PLCs and lock up
                ICS systems — a dealbreaker for OT/ICS environments. OdinForge uses configurable
                scan intensity with safety guardrails designed to prevent disruption in sensitive
                operational technology environments.
              </div>
              <div className="cp-adv-detail">
                <span className="tag">SAFETY</span>
                <span>
                  Validate security without risking production uptime. Configurable intensity for
                  sensitive environments.
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* COMPETITOR CREDIT */}
        <section className="cp-shannon-credit cp-reveal">
          <div className="cp-shannon-box">
            <div>
              <h3>Credit where it's due — NodeZero is a serious platform.</h3>
              <p>
                Horizon3.ai was founded by former JSOC and NSA operators. NodeZero was the first
                AI to solve the Game of Active Directory benchmark, and it serves a third of the
                Fortune 10. Their autonomous pentesting approach has fundamentally changed how
                enterprises validate security.
              </p>
              <p style={{ marginTop: 16 }}>
                But their enterprise-only positioning and opaque pricing leave most security teams
                on the outside looking in. OdinForge opens the door.
              </p>
            </div>
            <div className="cp-shannon-list">
              <div className="cp-shannon-list-item">
                <span className="icon">{"\u2713"}</span>
                <span>
                  <strong>NodeZero excels at</strong> autonomous internal network pentesting and AD
                  exploitation at enterprise scale
                </span>
              </div>
              <div className="cp-shannon-list-item">
                <span className="icon">{"\u2713"}</span>
                <span>
                  <strong>NodeZero excels at</strong> unlimited on-demand testing with one-click
                  fix verification
                </span>
              </div>
              <div className="cp-shannon-list-item">
                <span className="icon">&rarr;</span>
                <span>
                  <strong>OdinForge adds</strong> transparent pricing and accessibility for
                  mid-market teams
                </span>
              </div>
              <div className="cp-shannon-list-item">
                <span className="icon">&rarr;</span>
                <span>
                  <strong>OdinForge adds</strong> production-ready web app testing and visual
                  breach chains
                </span>
              </div>
              <div className="cp-shannon-list-item">
                <span className="icon">&rarr;</span>
                <span>
                  <strong>OdinForge adds</strong> safe OT/ICS scanning and native multi-tenant
                  architecture
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="cp-cta-section" id="cta">
          <div className="cp-cta-box cp-reveal">
            <h2>Enterprise-grade validation. Accessible pricing.</h2>
            <p>
              Start a free trial and see what OdinForge finds — no custom quotes, no
              procurement cycles, no Docker containers.
            </p>
            <div className="cp-cta-actions">
              <a href="/signup" className="cp-btn-primary">
                Start Free Trial &rarr;
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
            2026. NodeZero information sourced from{" "}
            <a
              href="https://horizon3.ai"
              target="_blank"
              rel="noopener noreferrer"
            >
              public documentation
            </a>{" "}
            and{" "}
            <a
              href="https://www.peerspot.com/products/the-nodezero-platform-by-horizon3-ai-reviews"
              target="_blank"
              rel="noopener noreferrer"
            >
              verified peer reviews
            </a>
            .
          </p>
        </footer>
      </div>
    </div>
  );
}
