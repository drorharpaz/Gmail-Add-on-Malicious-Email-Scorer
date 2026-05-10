# Project Technical Deep-Dive — Gmail Security Shield

This document is a **senior-level preparation guide** for technical interviews. It explains the architecture, security posture, and trade-offs of the **Malicious Email Scorer**: a Gmail add-on plus a Python backend on **Google Cloud Run**.

---

## 1. The Strategy Behind the README

The [`README.md`](README.md) is structured as a **reviewer-first artifact**, not a tutorial diary. The rationale for each major block is:

| Section | Purpose |
|---------|---------|
| **Title and one-line value proposition** | Immediately answers *what* the system does and *for whom* (users get verdicts in-context). Reviewers scan this in seconds. |
| **Core capabilities (table)** | Maps product language to concrete detectors (spoofing, URLHaus, scoring). Shows you understand **threat modeling**, not only code. |
| **Architecture and design decisions** | Explains *why* the system is shaped this way—modular engine, discovery, fallback, Cloud Run. This separates **junior** (“it works”) from **senior** (“it works for reasons we can defend”). |
| **Security best practices** | Demonstrates **security awareness** aligned with how cloud and Workspace teams operate: secrets, least-privilege OAuth, URL allowlists, TLS posture. |
| **Setup and deployment** | Proves reproducibility: copy-paste commands, Secret Manager wiring, manifest alignment. |
| **Testing** | Shows **verification discipline**: pytest layout mirrors `PYTHONPATH` in production. |
| **Future roadmap** | Signals **product thinking** (SPF/DKIM, explainability, observability) without over-promising on scope. |

### Why emphasize **Security Awareness**?

Cybersecurity reviewers look for evidence that you **treat untrusted input, credentials, and scope as first-class risks**. Calling out Secret Manager, OAuth minimization, and `urlFetchWhitelist` in the README:

- Shows you **anticipate** supply-chain and abuse scenarios (e.g., arbitrary outbound fetch from Apps Script).
- Aligns with **defense-in-depth**: even if the backend is the “brain,” the add-on surface is still an attack and privacy boundary.

### Why emphasize **Design Decisions**?

Technical stakeholders want to know you can **articulate trade-offs**:

- *Dynamic discovery* vs. static registration  
- *Serverless* vs. always-on VMs  
- *Fallback registration* vs. “fail closed”  

Documenting those choices **builds trust** because it proves the implementation is not accidental—it is **reviewable and evolvable**.

### Communication style and trust

The README uses **tables, explicit file pointers, and operational commands**. That style:

- Reduces ambiguity for **security reviewers** who audit both behavior and process.
- Mirrors **internal design docs** (problem → architecture → threats → deployment), which is the dialect many security companies use.
- Avoids marketing fluff; **concrete scopes and endpoints** signal engineering maturity.

---

## 2. Frontend: Gmail Add-on (Apps Script)

The add-on consists of [`gmail-addon/Code.gs`](gmail-addon/Code.gs) and [`gmail-addon/appsscript.json`](gmail-addon/appsscript.json). Below is a structured walkthrough of **why** each part exists.

### 2.1 `appsscript.json` — manifest and policy

| Field / block | Role |
|---------------|------|
| **`timeZone`** | Consistent scheduling and logging semantics for the script project (e.g. `Asia/Jerusalem`). |
| **`runtimeVersion: V8`** | Modern JavaScript runtime; better compatibility with current Apps Script patterns. |
| **`exceptionLogging: STACKDRIVER`** | Surfaces errors in **Google Cloud Logging** (observability for production debugging). |
| **`oauthScopes`** | Declares **minimum** Google API access the add-on requests at install/authorization time. |
| **`urlFetchWhitelist`** | Declares **allowed URL prefixes** for `UrlFetchApp.fetch`. Requests outside this list fail at runtime—**network allowlisting** for the script. |
| **`addOns.common`** | Branding: name, logo URL, `useLocaleFromApp` (locale follows Gmail). |
| **`addOns.gmail.contextualTriggers`** | Binds the add-on to **Gmail UI events** (here: opening a message). |

#### OAuth scopes — significance and least privilege

| Scope | Why it is included |
|-------|-------------------|
| **`gmail.addons.execute`** | **Required** for Gmail add-ons to run in the Gmail UI context. |
| **`gmail.readonly`** | Read message content and metadata to build the analysis payload **without** implying send/draft rights. |
| **`script.external_request`** | **Required** to call the Cloud Run backend via `UrlFetchApp`. |
| **`gmail.modify`** | Enables **mutating** operations (e.g. a “delete” button flow). In a stricter production review, you would **drop this** if no code path performs writes—**least privilege**. |
| **`script.locale`** | Pairs with `useLocaleFromApp` for localized UI strings. |

**Interview framing:** *We declared scopes explicitly in the manifest so users and admins see the blast radius up front. Read-only analysis uses `gmail.readonly`; any write scope should be justified by a real feature or removed.*

#### `urlFetchWhitelist` — significance

The whitelist entry is an **HTTPS prefix** of the Cloud Run service (trailing slash is a common convention for prefix matching). It:

- **Limits** where the script can send HTTP requests, reducing risk if the project were compromised or abused.
- **Forces** alignment between **manifest policy** and **`BACKEND_BASE_URL`** in `Code.gs`.

**Interview framing:** *This is the Apps Script equivalent of an egress allowlist: even with `external_request`, we do not permit arbitrary URLs.*

### 2.2 `Code.gs` — execution path

**Entry: `onGmailMessageOpen(e)`**

- **`e.gmail.messageId`** identifies the open message.
- **`e.gmail.accessToken`** is a **short-lived, contextual token** for that message.
- **`GmailApp.setCurrentMessageAccessToken(accessToken)`** scopes subsequent `GmailApp` reads to the **current** message—correct pattern for contextual add-ons.

**Why `onGmailMessageOpen` as a contextual trigger?**

- Fires **when the user’s attention is on a specific message**—ideal for “analyze what I’m looking at.”
- Avoids **batch** scanning the entire mailbox (different privacy and performance profile).
- Matches Gmail’s **Card UI** model: return cards from the trigger function.

**`getAnalysisFromBackend(messageId)`**

- **`GmailApp.getMessageById(messageId)`** loads the message after token scoping.
- Builds **`payload`**: subject, sender, date, bodies, raw—**structured untrusted input** for the backend.
- **`UrlFetchApp.fetch`** with `method: post`, `contentType: application/json`, `muteHttpExceptions: true`:
  - POST matches REST semantics for analysis.
  - `muteHttpExceptions` lets you **parse** error bodies instead of throwing immediately.
- **`ngrok-skip-browser-warning`** header is a **legacy/dev convenience** for tunneling; harmless on Cloud Run but can be removed in a pure-production deployment.

**`buildSecurityCard` / `createErrorCard`**

- Maps **`result.label`** (`safe` / `suspicious` / `malicious`) to **CardService** widgets—clear UX contract with the backend.
- **`deleteEmailAction`** (if implemented end-to-end) would require **`gmail.modify`** and careful confirmation UX.

#### Why `getPlainBody()` and `getRawContent()`?

| API | Purpose |
|-----|---------|
| **`getPlainBody()`** | **Normalized text** for fast heuristics (regexes, keyword checks) without HTML noise. Reduces parser differential bugs for simple rules. |
| **`message.getBody()`** (HTML) | Preserves **markup and hrefs** for link extraction (e.g. URL pattern matching, future DOM-aware analysis). |
| **`getRawContent()`** | Full **RFC 5322-style** source including **headers** (`Received`, `Authentication-Results`, etc.). Enables future checks on **SPF/DKIM/DMARC** alignment and header anomalies—essential for senior phishing analysis. |

**Interview framing:** *Plain body is for cheap signals; raw is for authenticity and protocol-level signals. We accept larger payloads to avoid losing evidence.*

### 2.3 Future growth (advanced capabilities)

1. **User-reported phishing feedback** — “Was this helpful?” / false-positive reporting stored in **Firestore** or **BigQuery** with privacy controls; feeds model or rule tuning.
2. **Admin audit integration** — Stream anonymized verdict metrics to **Google Workspace** admin logs or **SIEM** via **Pub/Sub** for org-wide visibility (with consent and DLP).
3. **Safe link unwrapping** — Resolve redirect chains server-side with **timeouts and size limits** to detect URL shortener abuse.
4. **Attachment sandbox metadata** — If policies allow, send **hashes** (not raw binaries) to **VT** or internal reputation—never exfiltrate user content without policy.
5. **Progressive disclosure UI** — Expandable card sections for **per-check explanations** and recommended actions (report phish, contact IT).

---

## 3. Backend: The Modular Security Engine

### 3.1 Request path: `/analyze` hits Flask

ASCII flow from HTTP to response:

```
  Apps Script (HTTPS POST JSON)
           |
           v
+------------------+
|  Gunicorn worker |
|  Flask `main:app`|
+--------+---------+
         |
         v
   POST /analyze
         |
         v
  request.get_json()  -->  email_metadata (dict)
         |
         v
  security_engine.execute_analysis(email_metadata)
         |
         v
  jsonify(analysis_result)  -->  200 JSON
```

**Module load (once per worker):** `security_engine = SecurityEngine()` runs **`_discover_checks()`** at import time, so check registration cost is paid at **cold start**, not per request.

### 3.2 Simulation: suspicious email end-to-end

**Scenario:** Display name impersonates a brand; body contains a URL; headers in raw content could support future authentication checks.

1. **Extraction (Apps Script)**  
   Payload includes `sender`, `body`, `htmlBody`, `rawContent`, etc.

2. **Ingress (Flask)**  
   `analyze_email` validates JSON presence, then calls `execute_analysis`.

3. **Discovery (startup, not per request)**  
   - Import `security_shield.checks`.  
   - `pkgutil.iter_modules` discovers submodules.  
   - For each module, `inspect.getmembers` finds `BaseCheck` subclasses; **`is_active`** gates registration.  
   - If count is **zero**, **manual fallback** imports `DomainSpoofingCheck` and `URLHausCheck` explicitly.

4. **Execution (per request)**  
   For each check in order: `run(email_data)` → `(is_threat, priority)`.

5. **Scoring**  
   - Accumulate **priority** into `total_score`.  
   - **Veto:** if `total_score >= 10`, stop further checks (`veto_triggered`).  
   - **Label mapping:**  
     - `malicious` if `total_score >= 9` or veto  
     - `suspicious` if `3 <= score <= 8`  
     - else `safe`

6. **Response**  
   JSON: `score`, `label`, `findings` (per-check name, description, priority), `timestamp`.

### 3.3 Tooling choices

| Choice | Reason | Trade-off |
|--------|--------|-----------|
| **Flask** | Minimal, explicit HTTP layer; easy to reason about for a **single primary endpoint** and a few diagnostics. | Not async-first; fine for CPU-light scoring at modest QPS. |
| **Gunicorn** | Production **WSGI** server; multiple threads/workers; standard on Cloud Run. | Requires correct **`PORT`** binding and worker model tuning for CPU-bound work. |
| **`pkgutil` + `importlib`** | **Dynamic discovery** of checks in `security_shield.checks` without a central registry file. | Failures can be **silent** if broad `except` hides bugs—mitigated by logging and `/debug/checks`. |

**Dynamic discovery vs. static registration**

| Dynamic discovery | Static registration |
|-------------------|---------------------|
| Add a file → often **no engine edit** | **Explicit** list in code: predictable, auditable |
| Slight **magic**; depends on import path in container | No import-path surprises |
| Good for **plugin-style** growth | Good for **highly regulated** builds with fixed modules |

**Our hybrid:** discovery first, **manual fallback** if zero checks—balances flexibility with **production certainty**.

### 3.4 Resilience: manual fallback

If the container **omits** check modules, misconfigures `PYTHONPATH`, or every dynamic import fails, discovery alone yields **zero checks** → all mail looks **safe**.

The fallback **explicitly** imports:

- `DomainSpoofingCheck`
- `URLHausCheck`

and instantiates them with **per-class error handling**, so one failing constructor does not necessarily block the other.

**Why critical for cloud:** container images and build pipelines are a **frequent** source of “works on my laptop” drift. Fallback turns a **silent total failure** into a **degraded but meaningful** posture—and log lines make the failure **visible**.

---

## 4. Architecture & Cloud Infrastructure

### 4.1 Cloud Run and serverless fit

**Why serverless (Cloud Run) fits this use case:**

- Traffic is **event-driven** (user opens a message → occasional bursts).  
- No need to run a **24/7** VM for a class project or early product.  
- **Managed TLS**, IAM integration, and **revision-based** rollbacks.

**Scale-to-zero:** when idle, Cloud Run can scale instances to **zero** (depending on configuration). You pay little when unused.

**Cold starts:** the first request after idle may pay **container start + Python import + `SecurityEngine()`** cost. In our design, **URLHaus** may fetch data during check `__init__`, which can **amplify** cold start latency—an improvement area (lazy refresh).

### 4.2 Secret Manager: mount secrets vs. hardcode

| Approach | Security implication |
|----------|----------------------|
| **Hardcoded in image or repo** | Anyone with image/registry/repo access gets the secret; rotation requires rebuild. **High risk.** |
| **Plain env in Cloud Run console** | Better than in git, but still visible to anyone with project deploy permissions; rotation is manual. |
| **Secret Manager + reference on service** | Secret **not** baked into layers; access **auditable** via IAM; rotation can move to **new versions** without code changes. |

**Interview answer:** *We treat URLHaus credentials as **server-side secrets**. Apps Script never receives that key; only our backend calls URLHaus.*

### 4.3 CI/CD: build and deploy, and Dockerfile intent

Typical flow:

1. **`docker build`** (locally or via Cloud Build) using root [`Dockerfile`](Dockerfile).  
2. **Push** image to **Artifact Registry**.  
3. **`gcloud run deploy`** with image reference, region, memory, **secret bindings**, and ingress settings.

**Dockerfile optimizations / choices:**

- **`python:3.11-slim`**: smaller attack surface and image than full images.  
- **Copy `requirements.txt` before full `src/`**: better **layer caching** when dependencies change rarely.  
- **`PYTHONPATH=/app/src`**: aligns with test and import layout (`security_shield.*`).  
- **`PYTHONUNBUFFERED`**: logs flush promptly in Cloud Logging.  
- **Gunicorn binds `0.0.0.0:$PORT`**: Cloud Run injects **`PORT`**.

### 4.4 Networking: Apps Script to Cloud Run

Google’s **Apps Script** runs in a **Google-managed execution environment** (isolated from your VPC by default). Interviewers sometimes refer informally to Google’s script execution stack (you may hear colloquial names such as **Beanserver** in older discussions); publicly this is documented as the **managed Apps Script runtime**. When `UrlFetchApp.fetch` runs:

```
  User Gmail Client
        |
        v
  Gmail + Apps Script host
        |
        |  contextual trigger + OAuth
        v
  Apps Script runtime  --HTTPS-->  Cloud Run (public HTTPS URL)
```

**Important points for interviews:**

- Traffic is **outbound HTTPS** from Google’s environment to your **public** Cloud Run URL (in this project: **unauthenticated** ingress for simplicity).  
- **Production hardening** might use **IAM / OAuth** on the backend or a **private** integration pattern—at the cost of complexity.  
- **`urlFetchWhitelist`** is the **client-side** egress control; **Cloud Armor** or **API keys** could be **server-side** additions.

---

## 5. Potential Interview Questions (Hard) — With Model Answers

### Q1. “Your backend trusts JSON from the add-on. How do you prevent abuse?”

**Answer:** *The add-on is a client. We treat the payload as **untrusted**: size limits, schema validation, and rate limiting would be the first hardening steps. For org deployments, we’d put **authenticated ingress** (e.g. verify Google-signed tokens or use VPC + internal LB) so arbitrary internet clients cannot spam `/analyze`. Today’s demo prioritizes integration clarity over zero-trust networking.*

### Q2. “Dynamic discovery hid a failure in production—how do you respond?”

**Answer:** *We added **logging** for `checks_path`, explicit counts, **`/health`**, **`/debug/checks`**, and a **manual fallback** so zero checks is not silent. Longer term I’d add a **startup probe** that fails the revision if zero checks, and integration tests that assert the **Docker image** contains `security_shield.checks`.*

### Q3. “Why expose `/debug/checks` in production?”

**Answer:** *It’s a **diagnostic** endpoint for demos and early ops. In production I’d **gate** it behind auth, IP allowlists, or remove it entirely and rely on structured logs. The principle is: **observability without leaking sensitive data**—we return names and paths, not user content.*

### Q4. “URLHaus in `__init__`—what breaks at cold start?”

**Answer:** *Network I/O during check construction **blocks** worker readiness and couples availability to URLHaus. I’d move to **lazy download** on a timer or first request, with **timeouts**, **max size**, and **circuit breaking**. Secrets would stay in Secret Manager, never logged.*

### Q5. “How would you map this to STRIDE or a threat model?”

**Answer:** ***Spoofing:** fake backend or DNS—mitigate with TLS, pinning in client where possible, and custom domains. **Tampering:** HTTPS + signed tokens if we add auth. **Repudiation:** correlation IDs and audit logs for verdicts. **Information disclosure:** avoid returning stack traces to clients; redact logs. **DoS:** rate limit and cap body size. **Elevation:** least-privilege OAuth; no broad `gmail` scope without need.*

---

## Closing

This project demonstrates a **full vertical slice**: Workspace UX, controlled egress, a **pluggable** analysis engine, and **serverless** deployment—with explicit attention to **failure modes** (empty checks) and **secret hygiene**. Use this document to narrate **trade-offs**, not only features.
