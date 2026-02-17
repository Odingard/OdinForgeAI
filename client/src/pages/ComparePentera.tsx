import { useEffect, useRef } from "react";
import "./compare-shannon.css";

export default function ComparePentera() {
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
            Pentera charges $100K+.
            <br />
            <span className="accent">
              OdinForge delivers more
              <br />
              for a fraction of the cost.
            </span>
          </h1>
          <p className="cp-hero-sub">
            Pentera is a well-funded automated pentesting platform built for large enterprises.
            But its six-figure price tag, 500-IP minimums, and rigid licensing lock out the teams
            that need security validation most. OdinForge delivers full-spectrum adversarial
            exposure validation — accessible to every security team.
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
              <span className="hl">90</span>%
            </div>
            <div className="cp-stat-label">Lower cost of entry vs Pentera</div>
          </div>
          <div className="cp-stat-item">
            <div className="cp-stat-value">
              <span className="hl">0</span> Minimums
            </div>
            <div className="cp-stat-label">No 500-IP floor &middot; Scale at your pace</div>
          </div>
          <div className="cp-stat-item">
            <div className="cp-stat-value">
              <span className="hl">Visual</span> Chains
            </div>
            <div className="cp-stat-label">Interactive breach chain visualization</div>
          </div>
        </div>

        {/* COMPARISON TABLE */}
        <section className="cp-section cp-reveal" id="comparison">
          <div className="cp-section-label">Feature Comparison</div>
          <div className="cp-section-title">OdinForge vs Pentera — no spin.</div>
          <p className="cp-section-desc">
            An honest comparison of capabilities, pricing, and deployment. Both platforms validate
            security — the difference is who can actually use them.
          </p>

          <table className="cp-table">
            <thead>
              <tr>
                <th>Capability</th>
                <th>&#x2B21; OdinForge</th>
                <th>Pentera</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Pricing</td>
                <td><span className="cp-check">Transparent, accessible tiers</span></td>
                <td><span className="cp-miss">~$100K+/year, opaque quoting</span></td>
              </tr>
              <tr>
                <td>Minimum Requirements</td>
                <td><span className="cp-check">No minimums — start with 1 asset</span></td>
                <td><span className="cp-miss">500 IP minimum, domain floors</span></td>
              </tr>
              <tr>
                <td>Deployment</td>
                <td><span className="cp-check">SaaS — zero hardware required</span></td>
                <td><span className="cp-limited">On-prem appliance (8-16 CPUs, 64GB RAM)</span></td>
              </tr>
              <tr>
                <td>Attack Surface</td>
                <td><span className="cp-check">Infra, cloud, network, web apps, APIs</span></td>
                <td><span className="cp-check">Internal, external, cloud (AWS/Azure)</span></td>
              </tr>
              <tr>
                <td>Breach Chain Visualization</td>
                <td><span className="cp-check">Interactive animated attack paths</span></td>
                <td><span className="cp-limited">Attack path view, less transparent methodology</span></td>
              </tr>
              <tr>
                <td>Kill Chain Emulation</td>
                <td><span className="cp-check">Full kill chain with evidence</span></td>
                <td><span className="cp-check">Full kill chain emulation (non-destructive)</span></td>
              </tr>
              <tr>
                <td>MITRE ATT&CK Mapping</td>
                <td><span className="cp-check">Full framework coverage</span></td>
                <td><span className="cp-check">Full framework alignment</span></td>
              </tr>
              <tr>
                <td>Remediation Guidance</td>
                <td><span className="cp-check">Prioritized with code-level fixes</span></td>
                <td><span className="cp-check">AI-powered remediation (Pentera Resolve)</span></td>
              </tr>
              <tr>
                <td>License Flexibility</td>
                <td><span className="cp-check">Scale up or down anytime</span></td>
                <td><span className="cp-miss">Cannot revoke IPs once imported</span></td>
              </tr>
              <tr>
                <td>Multi-Tenant</td>
                <td><span className="cp-check">Built-in multi-org with RLS isolation</span></td>
                <td><span className="cp-limited">Enterprise feature, extra cost</span></td>
              </tr>
              <tr>
                <td>Continuous Monitoring</td>
                <td><span className="cp-check">24/7 posture monitoring &amp; drift detection</span></td>
                <td><span className="cp-limited">Scheduled re-testing</span></td>
              </tr>
              <tr>
                <td>Agentless</td>
                <td><span className="cp-check">Fully agentless, SaaS-delivered</span></td>
                <td><span className="cp-check">Agentless (appliance-based)</span></td>
              </tr>
              <tr>
                <td>Enterprise Scale</td>
                <td><span className="cp-check">10K+ asset environments</span></td>
                <td><span className="cp-check">Large enterprise proven</span></td>
              </tr>
              <tr>
                <td>Time to Value</td>
                <td><span className="cp-check">Minutes — sign up and scan</span></td>
                <td><span className="cp-limited">Weeks — procurement, appliance setup, config</span></td>
              </tr>
            </tbody>
          </table>
        </section>

        {/* ADVANTAGES */}
        <section className="cp-section cp-reveal">
          <div className="cp-section-label">Why OdinForge</div>
          <div className="cp-section-title">Where OdinForge goes further.</div>
          <p className="cp-section-desc">
            Pentera built a strong product for Fortune 500 budgets. OdinForge brings that same
            power to every security team.
          </p>

          <div className="cp-advantages-grid">
            <div className="cp-adv-card">
              <div className="cp-adv-number">01</div>
              <div className="cp-adv-title">
                Enterprise power.
                <br />
                Startup pricing.
              </div>
              <div className="cp-adv-desc">
                Pentera's average deal is ~$100K/year with a 500-IP minimum. That prices out most
                mid-market teams and growing startups. OdinForge delivers automated breach simulation,
                full kill-chain validation, and visual attack paths at a fraction of the cost — with
                no asset minimums.
              </div>
              <div className="cp-adv-detail">
                <span className="tag">PRICING</span>
                <span>
                  No six-figure commitments. No IP floors. Start with what you have, scale as you grow.
                </span>
              </div>
            </div>

            <div className="cp-adv-card">
              <div className="cp-adv-number">02</div>
              <div className="cp-adv-title">
                SaaS-first.
                <br />
                No appliance required.
              </div>
              <div className="cp-adv-desc">
                Pentera requires an on-premises virtual or physical appliance — 8-16 CPUs, 64GB RAM,
                ~1TB storage. That means procurement cycles, rack space, and dedicated infrastructure
                management. OdinForge runs entirely in the cloud. Sign up, point it at your targets,
                and start validating in minutes.
              </div>
              <div className="cp-adv-detail">
                <span className="tag">DEPLOY</span>
                <span>
                  Zero hardware. Zero procurement. Zero rack space. Just security validation.
                </span>
              </div>
            </div>

            <div className="cp-adv-card">
              <div className="cp-adv-number">03</div>
              <div className="cp-adv-title">
                Flexible licensing
                <br />
                that works for you.
              </div>
              <div className="cp-adv-desc">
                Pentera customers report that once IPs are imported into the platform, licenses
                cannot be revoked — even if assets are decommissioned. OdinForge lets you scale up
                or down freely. Decommission an asset? Your license adjusts. No lock-in, no wasted
                spend.
              </div>
              <div className="cp-adv-detail">
                <span className="tag">LICENSE</span>
                <span>
                  Your infrastructure changes. Your security tooling should change with it.
                </span>
              </div>
            </div>

            <div className="cp-adv-card">
              <div className="cp-adv-number">04</div>
              <div className="cp-adv-title">
                Built for MSSPs
                <br />
                from day one.
              </div>
              <div className="cp-adv-desc">
                OdinForge's architecture is multi-tenant by design with row-level security isolation
                between organizations. MSSPs can serve multiple clients from a single deployment with
                complete data separation — no per-client appliances needed. Pentera's multi-tenant
                capabilities are an enterprise add-on, not a core feature.
              </div>
              <div className="cp-adv-detail">
                <span className="tag">MULTI-TENANT</span>
                <span>
                  One platform, unlimited organizations. True isolation, not bolted-on access controls.
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* COMPETITOR CREDIT */}
        <section className="cp-shannon-credit cp-reveal">
          <div className="cp-shannon-box">
            <div>
              <h3>Credit where it's due — Pentera is a proven platform.</h3>
              <p>
                Pentera pioneered automated security validation and serves 1,100+ enterprises
                across 65 countries. Their non-destructive, agentless approach and full kill-chain
                emulation set the standard for the AEV market. If you have the budget and
                infrastructure for an on-prem appliance, it's a solid choice.
              </p>
              <p style={{ marginTop: 16 }}>
                But most security teams don't have $100K and a dedicated appliance team. That's
                where OdinForge steps in.
              </p>
            </div>
            <div className="cp-shannon-list">
              <div className="cp-shannon-list-item">
                <span className="icon">{"\u2713"}</span>
                <span>
                  <strong>Pentera excels at</strong> non-destructive kill-chain emulation in
                  production environments
                </span>
              </div>
              <div className="cp-shannon-list-item">
                <span className="icon">{"\u2713"}</span>
                <span>
                  <strong>Pentera excels at</strong> enterprise-scale internal network penetration
                  testing
                </span>
              </div>
              <div className="cp-shannon-list-item">
                <span className="icon">&rarr;</span>
                <span>
                  <strong>OdinForge adds</strong> accessible pricing with no IP minimums or
                  appliance requirements
                </span>
              </div>
              <div className="cp-shannon-list-item">
                <span className="icon">&rarr;</span>
                <span>
                  <strong>OdinForge adds</strong> SaaS delivery with minutes-to-value instead of
                  weeks
                </span>
              </div>
              <div className="cp-shannon-list-item">
                <span className="icon">&rarr;</span>
                <span>
                  <strong>OdinForge adds</strong> native multi-tenant architecture for MSSPs and
                  service providers
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="cp-cta-section" id="cta">
          <div className="cp-cta-box cp-reveal">
            <h2>Why pay $100K to validate your security?</h2>
            <p>
              Start a free trial and see what OdinForge finds in your environment — no
              procurement, no appliance, no commitment.
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
            2026. Pentera information sourced from{" "}
            <a
              href="https://pentera.io"
              target="_blank"
              rel="noopener noreferrer"
            >
              public documentation
            </a>{" "}
            and{" "}
            <a
              href="https://www.peerspot.com/products/pentera-reviews"
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
