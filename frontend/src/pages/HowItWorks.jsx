import { Link } from "react-router-dom";

const PIPELINE = [
  {
    step: "01",
    title: "Authorised target",
    body: "The analyst picks a case and a local lab URL. Anything that is not localhost or a Docker lab name is rejected before a request is sent.",
  },
  {
    step: "02",
    title: "Live fingerprint",
    body: "A single unauthenticated GET checks reachability, security headers, and stack hints. No exploit payloads, no fuzzing, no credential stuffing.",
  },
  {
    step: "03",
    title: "Training catalog",
    body: "For Juice Shop and DVWA, known vulnerability classes are loaded from a mapped catalog so the dashboard can teach OWASP coverage without attacking the app.",
  },
  {
    step: "04",
    title: "Normalise & store",
    body: "Results are written to the shared JSON contract, persisted with Case ID and Scan ID, then rendered on the dashboard and in an exportable report.",
  },
];

const TEAM = [
  {
    name: "Charles Buenaventura",
    role: "Frontend · Project management · Video",
    focus: "Dashboard, navigation, demo recording, and keeping the story coherent for mixed audiences.",
  },
  {
    name: "Carly Broodryk",
    role: "Frontend · Integration · Slides",
    focus: "Wiring scan JSON into the GUI, usability, and presentation documentation.",
  },
  {
    name: "Jayden Galanis",
    role: "Backend · Scanner",
    focus: "Python scanning engine, OWASP mapping, and positive/negative result shape.",
  },
  {
    name: "Joshua Telisman",
    role: "Backend · Database · Labs",
    focus: "Juice Shop / DVWA lab, case schema, and mapping findings to OWASP, NIST, and SANS.",
  },
];

export default function HowItWorks() {
  return (
    <>
      <div className="page-head">
        <div>
          <p className="kicker">Vector Zero · UTS 41909 Capstone</p>
          <h2>How WebSET works</h2>
          <p className="lede">
            Small teams ship web apps that attackers can probe in minutes. Enterprise scanners exist,
            but they are priced and staffed for organisations that already have a security function.
            WebSET is a teaching-first evaluation workflow: scan an authorised lab, map findings to
            public frameworks, and leave a case history a non-specialist can actually read.
          </p>
        </div>
        <Link className="btn" to="/scan">
          Open the demo
        </Link>
      </div>

      <section className="panel pitch">
        <h3>The problem we are solving</h3>
        <p>
          Web applications are deployed globally and often left with known classes of weakness —
          injection, broken access control, missing headers, leaked configuration. A breach is not
          only a technical failure. It is financial loss, regulatory exposure, and broken digital
          trust. Students, startups, and small product teams are frequently the ones shipping that
          code, yet tools such as Burp Suite Professional and Veracode sit outside their budget.
        </p>
        <p>
          Vector Zero built WebSET so those teams (and classrooms) can run a <b>repeatable</b>{" "}
          evaluation against apps they own, instead of ad-hoc manual checks with no case history.
        </p>
      </section>

      <section className="arch" aria-label="Architecture">
        <div className="arch-node">
          <small>01</small>
          <b>Local lab</b>
          <span>Juice Shop · DVWA</span>
        </div>
        <div className="arch-arrow">→</div>
        <div className="arch-node">
          <small>02</small>
          <b>Python engine</b>
          <span>Allow-list · headers · catalog</span>
        </div>
        <div className="arch-arrow">→</div>
        <div className="arch-node">
          <small>03</small>
          <b>JSON contract</b>
          <span>shared/scan-result.schema.json</span>
        </div>
        <div className="arch-arrow">→</div>
        <div className="arch-node">
          <small>04</small>
          <b>Case database</b>
          <span>SQLite · Case / Scan IDs</span>
        </div>
        <div className="arch-arrow">→</div>
        <div className="arch-node">
          <small>05</small>
          <b>Dashboard + report</b>
          <span>React GUI · HTML / JSON export</span>
        </div>
      </section>

      <h3 className="section-label">Design and methodology</h3>
      <div className="method-grid">
        {PIPELINE.map((item) => (
          <article className="panel method-card" key={item.step}>
            <span className="mono">{item.step}</span>
            <h3>{item.title}</h3>
            <p>{item.body}</p>
          </article>
        ))}
      </div>

      <div className="grid-2" style={{ marginTop: 14 }}>
        <section className="panel">
          <h3>What “static” and “dynamic” mean here</h3>
          <p className="lede" style={{ maxWidth: "none" }}>
            The proposal called for both. In this prototype they are scoped honestly.
          </p>
          <ul className="plain">
            <li>
              <b>Dynamic.</b> Live GET against the authorised host. Header gaps and stack
              fingerprinting only. If Docker is not running, the scan still completes using the
              catalog so the roadshow is not blocked.
            </li>
            <li>
              <b>Static / catalog.</b> Juice Shop and DVWA are deliberately vulnerable. Their
              documented defect classes are encoded as findings with OWASP, NIST, and SANS/CWE
              references. That is how we show coverage without sending attack strings.
            </li>
            <li>
              <b>Out of scope.</b> A04 Insecure Design is architectural. We mark it rather than
              pretending a code scan found it. Full A10 SSRF is not claimed on the Juice Shop
              catalog.
            </li>
          </ul>
        </section>
        <section className="panel">
          <h3>Why this stack</h3>
          <ul className="plain">
            <li>
              <b>Python + FastAPI</b> for the engine and API — matches the team’s backend ILC and
              is easy to demo from one command.
            </li>
            <li>
              <b>React dashboard</b> so totals, coverage, and drill-down stay usable for a mixed
              roadshow audience.
            </li>
            <li>
              <b>SQLite case store</b> so scan history survives a reboot without standing up a
              server.
            </li>
            <li>
              <b>Docker labs only</b> because scanning systems you do not own is illegal. The
              allow-list is a product feature, not a footnote.
            </li>
          </ul>
        </section>
      </div>

      <section className="panel" style={{ marginTop: 14 }}>
        <h3>Impact, limits, and what we are not claiming</h3>
        <div className="grid-2 tight">
          <div>
            <p>
              <b>Impact.</b> Give small teams and classrooms a free, readable loop: scan → map to
              OWASP → recommend a fix → keep history. Juice Shop is already used in teaching; WebSET
              shows how those flaws appear as scored findings rather than as a CTF write-up.
            </p>
            <p>
              Commercial suites still win on depth, authenticated crawling, and false-positive
              tuning. We compare ourselves on <i>usability and explainability</i> against
              ImmuniWeb, Pentest-tools, and SSLTrust-style reports, not on replacing Burp for a
              professional pentest.
            </p>
          </div>
          <div>
            <p>
              <b>Limits.</b> Catalog findings are not independent proof that a live instance is
              exploitable. False positives remain the main risk of any rule-based approach; we
              surface confidence and evidence so judges can see the distinction. Tech-stack
              coverage is two teaching stacks, not the whole web.
            </p>
            <p>
              Future work: more live (still non-exploitative) checks, authenticated sessions on labs
              we control, and trend analytics across many cases.
            </p>
          </div>
        </div>
      </section>

      <h3 className="section-label">Vector Zero</h3>
      <div className="team-grid">
        {TEAM.map((person) => (
          <article className="panel" key={person.name}>
            <h3>{person.name}</h3>
            <p className="mono">{person.role}</p>
            <p className="lede" style={{ marginTop: 10 }}>
              {person.focus}
            </p>
          </article>
        ))}
      </div>

      <section className="panel talk" style={{ marginTop: 14 }}>
        <h3>90-second demo path (roadshow)</h3>
        <ol className="plain">
          <li>
            Dashboard — cases, scans, severity, OWASP hits already seeded so the room sees a living
            product before anyone clicks Scan.
          </li>
          <li>
            New scan — Juice Shop case, localhost:3000. Point at the gold warning: external hosts
            are refused.
          </li>
          <li>
            Scan detail — progress bar, coverage grid, open a critical finding (OWASP / NIST / SANS
            + recommendation).
          </li>
          <li>Export HTML report — this is the artefact a small team would keep.</li>
        </ol>
        <p className="lede">
          If Docker is down, say so. Catalog findings still appear; that is an intentional demo
          resilience choice, not a hidden fake.
        </p>
      </section>
    </>
  );
}
