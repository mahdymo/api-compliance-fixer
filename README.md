# API Compliance Fixer — Trial Mode

Free trial with Google Forms feedback collection. No payment gateway.

## Quick deploy (Railway)

```bash
git init && git add . && git commit -m "init"
gh repo create api-compliance-fixer --public --push --source=.
# Then: Railway → New Project → Deploy from GitHub repo
```

Set environment variables in Railway dashboard (see below).

---

## Setting up Google Forms feedback (5 minutes)

### Step 1 — Create the form

1. Go to [forms.google.com](https://forms.google.com) → **Blank form**
2. Title it: `API Compliance Fixer — Trial Submissions`
3. Add these **Short answer** fields in order:
   - Name
   - Work Email
   - Company
   - Role
   - How did you hear about this? *(change to Dropdown: LinkedIn, Colleague/referral, GitHub, Web search, Twitter/X, Other)*
   - Use case
   - Collection name
   - Frameworks
   - Total changes
   - Format
   - Timestamp

### Step 2 — Get the entry IDs

1. Click the **three-dot menu (⋮)** at the top right → **Get pre-filled link**
2. Type any dummy value into every field (e.g. "test")
3. Click **Get link** → copy the URL
4. The URL looks like:
   ```
   https://docs.google.com/forms/d/e/1FAIpQLSe.../viewform?usp=pp_url
     &entry.1234567890=test
     &entry.2345678901=test
     ...
   ```
5. Your `GFORM_URL` is that same path with `/formResponse` at the end:
   ```
   https://docs.google.com/forms/d/e/1FAIpQLSe.../formResponse
   ```
6. Each `GFORM_*` variable maps to the `entry.XXXXXXXXXX` key for that field, in the order you created them.

### Step 3 — Link to a spreadsheet

1. In your form, click the **Responses** tab
2. Click the green **Sheets icon** → **Create a new spreadsheet**
3. Every submission now appears in the sheet in real time

### Step 4 — Set Railway environment variables

Copy the entry IDs from the pre-filled URL and paste them into Railway:

| Variable | Value |
|---|---|
| `BASE_URL` | Your Railway public URL |
| `GFORM_URL` | `https://docs.google.com/forms/d/e/.../formResponse` |
| `GFORM_NAME` | `entry.XXXXXXXXXX` for the Name field |
| `GFORM_EMAIL` | `entry.XXXXXXXXXX` for Work Email |
| `GFORM_COMPANY` | `entry.XXXXXXXXXX` for Company |
| `GFORM_ROLE` | `entry.XXXXXXXXXX` for Role |
| `GFORM_HOW_HEARD` | `entry.XXXXXXXXXX` for How heard |
| `GFORM_USE_CASE` | `entry.XXXXXXXXXX` for Use case |
| `GFORM_COLLECTION` | `entry.XXXXXXXXXX` for Collection name |
| `GFORM_FRAMEWORKS` | `entry.XXXXXXXXXX` for Frameworks |
| `GFORM_CHANGES` | `entry.XXXXXXXXXX` for Total changes |
| `GFORM_FORMAT` | `entry.XXXXXXXXXX` for Format |
| `GFORM_TIMESTAMP` | `entry.XXXXXXXXXX` for Timestamp |

### What happens if GFORM_URL is not set?

The app still works — submissions are logged to Railway's stdout (visible in the logs tab) and users still get their download. You can add the form config any time without redeploying code.

---

## API endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Dashboard UI |
| `GET` | `/api/frameworks` | List frameworks + rules |
| `GET` | `/api/health` | Health check (shows gform_configured) |
| `POST` | `/api/upload` | Upload file, get changelog preview |
| `POST` | `/api/trial` | Submit trial form → get download token |
| `POST` | `/api/feedback` | Post-download rating/comment |
| `GET` | `/api/download/{token}` | Download compliant ZIP (one-time) |

## Project structure

```
api-compliance-fixer/
├── main.py          # FastAPI app — Google Forms integration
├── transform.py     # Postman + OpenAPI transformer
├── frameworks.py    # SAMA, PCI-DSS, NIS2, GDPR, DORA rules
├── static/
│   └── index.html   # Dashboard UI
├── requirements.txt
├── Dockerfile
├── railway.json
└── .env.example     # All env vars with setup instructions
```
