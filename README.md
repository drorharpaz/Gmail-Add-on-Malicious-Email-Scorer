# Gmail Security Shield — Malicious Email Scorer

**Gmail Security Shield** is a contextual Gmail add-on backed by a Python security service that scores opened messages for phishing risk and returns a clear verdict with structured findings—so users get **actionable context** without leaving their inbox.

---

## Core Capabilities

| Capability | Description |
|------------|-------------|
| **Phishing-oriented scoring** | Aggregates signals into a numeric score and labels: `safe`, `suspicious`, or `malicious`. |
| **Domain spoofing detection** | Flags high-value brand names in the display name when the message does not originate from an expected domain (e.g. “PayPal” with a consumer mailbox domain). |
| **URLHaus integration** | Enriches analysis by matching extracted URLs against an Abuse.ch URLHaus export (authenticated feed), maintaining a local in-memory set for fast lookups. |

The add-on sends structured metadata (subject, sender, bodies, raw source) to **`POST /analyze`**; the backend runs all registered checks and returns JSON the UI can render.

---

## Architecture & Design Decisions

### High-level flow

1. **Gmail** opens a message → Apps Script trigger **`onGmailMessageOpen`** runs with a scoped access token.  
2. **Apps Script** reads message fields, **POST**s JSON to the Cloud Run service.  
3. **Security engine** runs checks in order, applies scoring rules (including veto thresholds), returns score, label, and findings.  
4. **Card UI** reflects the verdict (with optional follow-up actions where scopes allow).

### Modular security engine

- **`SecurityEngine`** ([`src/security_shield/backend/engine.py`](src/security_shield/backend/engine.py)) orchestrates analysis; each check implements **`BaseCheck`** ([`src/security_shield/backend/base_check.py`](src/security_shield/backend/base_check.py)) with a consistent `run(email_data) -> (is_threat, priority)` contract.  
- Checks live in **`src/security_shield/checks/`** as independent modules—easy to extend, review, or disable per check.

### Dynamic discovery

- At startup, the engine imports the **`security_shield.checks`** package and uses **`pkgutil.iter_modules`** to load every submodule and register concrete **`BaseCheck`** subclasses.  
- **Why:** New checks can be dropped in as files without editing a central registry—clean separation of concerns and a pattern familiar to security tooling teams.

### Manual registration fallback (cloud resilience)

- If discovery registers **zero** checks (e.g. packaging or import edge cases in a container), the engine **explicitly** imports and instantiates **`DomainSpoofingCheck`** and **`URLHausCheck`**.  
- **Why:** Production behavior stays predictable; reviewers can still see checks active via **`GET /health`** and **`GET /debug/checks`**.

### Why **Google Cloud Run**

| Factor | Benefit |
|--------|---------|
| **Serverless operations** | No VM fleet to patch; revisions and rollbacks are first-class. |
| **Scale to zero / on demand** | Fits variable add-on traffic and cost-sensitive serverless workloads. |
| **HTTPS & IAM** | TLS termination and Google-managed ingress; integrate with Secret Manager and service accounts. |
| **Container portability** | Same image runs locally and in **`me-west1`** (or any region you choose). |

The service is served with **Gunicorn**; **`PYTHONPATH=/app/src`** matches the **`src/`**-first layout used in tests.

---

## Security Best Practices

| Practice | How it applies here |
|----------|---------------------|
| **GCP Secret Manager** | Store secrets such as **`URLHAUS_AUTH_KEY`** in Secret Manager; mount them as environment variables (or files) on Cloud Run. **Do not** commit `.env` or bake keys into images. Grant the runtime service account **`secretmanager.secretAccessor`** only on the secrets it needs. |
| **OAuth scopes (least privilege)** | The add-on manifest ([`gmail-addon/appsscript.json`](gmail-addon/appsscript.json)) requests **`gmail.addons.execute`**, **`gmail.readonly`** (read message content for analysis), **`script.external_request`** (call the backend), and optional **`gmail.modify`** only if destructive actions (e.g. delete) are implemented. **`script.locale`** aligns with **`useLocaleFromApp`**. Remove scopes you do not use before production review. |
| **URL Fetch whitelisting** | **`urlFetchWhitelist`** restricts **`UrlFetchApp.fetch`** to your backend origin—reducing open redirect / SSRF-style abuse from the script project. Keep **`BACKEND_BASE_URL`** in [`gmail-addon/Code.gs`](gmail-addon/Code.gs) aligned with the same host prefix as the manifest. |
| **Transport** | The backend sets **HSTS** on responses; clients should always call the **HTTPS** Cloud Run URL. |

---

## Setup & Deployment

### Prerequisites

- **Google Cloud** project with **Cloud Run** and **Artifact Registry** (or Container Registry) enabled.  
- **gcloud** CLI authenticated (`gcloud auth login`, `gcloud config set project YOUR_PROJECT_ID`).  
- **Docker** (local build) or use **`gcloud run deploy --source`**.

Replace placeholders: **`YOUR_PROJECT_ID`**, **`YOUR_REGION`** (e.g. `me-west1`), **`YOUR_SERVICE_NAME`**, **`AR_REPO`** (Artifact Registry repository name).

### Backend — build and deploy (example)

**Option A — build locally, push, deploy**

```bash
# From repository root
export PROJECT_ID=YOUR_PROJECT_ID
export REGION=YOUR_REGION
export SERVICE=YOUR_SERVICE_NAME
export IMAGE=${REGION}-docker.pkg.dev/${PROJECT_ID}/AR_REPO/${SERVICE}:latest

gcloud auth configure-docker ${REGION}-docker.pkg.dev

docker build -t "${IMAGE}" .
docker push "${IMAGE}"

gcloud run deploy "${SERVICE}" \
  --image "${IMAGE}" \
  --region "${REGION}" \
  --platform managed \
  --allow-unauthenticated \
  --set-secrets "URLHAUS_AUTH_KEY=URLHAUS_AUTH_KEY:latest" \
  --memory 512Mi
```

> Adjust **`--set-secrets`** to your Secret Manager secret name and version. If you use a plain env var for development only: **`--set-env-vars URLHAUS_AUTH_KEY=...`** (not recommended for production).

**Option B — source deploy (builds from Dockerfile in repo)**

```bash
gcloud run deploy YOUR_SERVICE_NAME \
  --source . \
  --region YOUR_REGION \
  --allow-unauthenticated \
  --set-secrets "URLHAUS_AUTH_KEY=URLHAUS_AUTH_KEY:latest"
```

After deploy, note the **Service URL** (e.g. `https://YOUR_SERVICE-xxxxx.YOUR_REGION.run.app`).

### Backend — useful endpoints

| Method | Path | Purpose |
|--------|------|---------|
| **POST** | `/analyze` | Main analysis API for the add-on. |
| **GET** | `/health` | Quick check: how many checks registered. |
| **GET** | `/debug/checks` | JSON: check names, `sys.path`, working directory (for diagnosing Cloud Run). |

### Gmail add-on — Google Apps Script

1. Open [script.google.com](https://script.google.com) and create a **standalone** script project (or bound project per Google’s add-on publishing flow).  
2. Add files from [`gmail-addon/`](gmail-addon/): paste **`Code.gs`**, and set **Project Settings →** enable **`appsscript.json`** manifest; paste contents of [`gmail-addon/appsscript.json`](gmail-addon/appsscript.json).  
3. **Update URLs** to match your deployment:  
   - **`urlFetchWhitelist`**: prefix of your Cloud Run URL (trailing slash recommended).  
   - **`BACKEND_BASE_URL`** in **`Code.gs`**: same host, no trailing slash (code appends **`/analyze`**).  
4. **Save**, then **Deploy → Test deployments** (or publish) as a **Gmail add-on** per Google’s [add-on deployment](https://developers.google.com/workspace/add-ons/gmail/quickstart) documentation.  
5. Re-authorize the add-on after changing **OAuth scopes** or **whitelist** entries.

---

## Testing

The suite uses **pytest** with **`pythonpath = src`** ([`pyproject.toml`](pyproject.toml)) so imports match production layout.

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
pip install -r tests/requirements.txt
pip install -r src/security_shield/backend/requirements.txt

export URLHAUS_AUTH_KEY=testkey   # required for URLHaus mock test
pytest tests/ -v --ignore=tests/test_url_haus_live.py
```

| Area | What it validates |
|------|-------------------|
| **Architecture** | Engine discovers checks; each check is a **`BaseCheck`** with required attributes. |
| **Domain spoofing** | Malicious / suspicious / safe scenarios and scoring. |
| **URLHaus (mock)** | Blacklist matching with **`requests-mock`**, no live malware URLs. |
| **URLHaus (live)** | Optional; **`test_url_haus_live.py`** hits the real API—run only with care and real credentials. |

---

## Future Roadmap (product & security)

- **SPF / DKIM / DMARC signals** — Parse **`Authentication-Results`** (where available from Gmail metadata) to detect alignment failures vs. suspicious content.  
- **AI-driven summaries** — Short, user-safe explanations of *why* a message was flagged (no raw secret leakage), plus confidence derived from independent signal count.  
- **Lazy URLHaus refresh** — Background or on-first-request refresh with size/time bounds to improve cold-start latency.  
- **Structured audit logging** — Correlation IDs from the add-on to backend logs for support and demo narratives.

---

## Repository layout (reference)

```
src/security_shield/
  backend/          # Flask app, engine, BaseCheck
  checks/           # Pluggable checks (domain spoofing, URLHaus, …)
gmail-addon/        # Apps Script sources and manifest
tests/              # pytest suite
Dockerfile          # Cloud Run container
```

---
>>>>>>> 229fb24 (Docs: Update README and finalize v1.0)
