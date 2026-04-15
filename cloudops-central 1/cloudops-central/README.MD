# CloudOps Central — Backend Integration Guide

## Architecture

```
Browser (aws-cloudops-pro.html)
        │  HTTP / Bearer JWT
        ▼
FastAPI Server (main.py)  ← runs on port 8000
        │  sts:AssumeRole
        ▼
AWS STS ──► CloudWatch (each monitored account)
             Cost Explorer
             EC2 / RDS / Lambda describe APIs
```

---

## 1. Install & Run

```bash
cd backend/
pip install -r requirements.txt

# Option A: direct
uvicorn main:app --reload --port 8000

# Option B: with explicit host (for LAN access)
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Visit **http://localhost:8000/docs** for the interactive Swagger UI.

---

## 2. AWS IAM Setup

### In EACH account you want to monitor:

1. Go to **IAM → Roles → Create Role**
2. Choose **"Another AWS account"** as trusted entity
3. Enter your **central/management AWS account ID**
4. Attach the policy from `iam_setup.json → permissions_policy`
5. Name it `CloudOpsMonitorRole`
6. Note the Role ARN: `arn:aws:iam::TARGET_ACCOUNT_ID:role/CloudOpsMonitorRole`

### On your FastAPI server machine:

Option A — **EC2 instance role** (recommended for production):
- Attach a role to your EC2/ECS that allows `sts:AssumeRole` on `arn:aws:iam::*:role/CloudOpsMonitorRole`

Option B — **Local development with AWS credentials**:
```bash
aws configure
# Enter your central-account access key/secret
```

---

## 3. Wire Frontend → FastAPI

In `aws-cloudops-pro.html`, add the `api_client.js` script tag **before** your main `<script>`:

```html
<script src="api_client.js"></script>
```

Then replace the login function in your main script:

```js
// REPLACE doLogin() with:
async function doLogin() {
  const u = document.getElementById('l-user').value.trim();
  const p = document.getElementById('l-pass').value;
  document.getElementById('login-error').style.display = 'none';
  try {
    const data = await doLoginAPI(u, p);
    SESSION = { username: data.username, name: data.name, role: data.role,
                avatar: data.role === 'admin' ? '🔧' : '👁', accounts: 'all' };
    document.getElementById('login-screen').style.display = 'none';
    document.getElementById('app').style.display = 'block';
    applyRoleUI();
    navTo('overview');
    startClock();
    startPolling(30000);  // refresh every 30s
  } catch (e) {
    document.getElementById('login-error').style.display = 'block';
    document.getElementById('login-error').textContent = e.message;
  }
}
```

Replace `renderOverview()` to load real data:

```js
async function renderOverview() {
  try {
    const accounts = await fetchAccounts();
    // accounts is now live from CloudWatch
    // rest of your render logic stays the same
    // just use `accounts` instead of the static `ACCOUNTS` array
  } catch (e) {
    showToast('Failed to load accounts: ' + e.message, 'error');
  }
}
```

Replace `renderServiceDrilldown()` chart section:

```js
// Inside renderServiceDrilldown(), replace buildSvcCharts(svc) with:
const data = await fetchServiceMetrics(currentAccount.id, svc.name, '6h');
renderChartsFromAPI(data.charts, svc.color);
```

Replace onboard submit:

```js
async function submitOnboard() {
  const formData = {
    account_id: document.getElementById('ob-id').value.trim(),
    name: document.getElementById('ob-name').value.trim(),
    region: document.getElementById('ob-region').value,
    env: document.getElementById('ob-env').value,
    owner: document.getElementById('ob-owner').value.trim(),
    role_arn: document.getElementById('ob-role-arn').value.trim(),
    external_id: document.getElementById('ob-ext-id').value.trim() || null,
    services: [...document.querySelectorAll('#svc-checks .svc-check.checked')]
              .map(el => el.querySelector('.svc-check-label').textContent),
    cpu_threshold: parseFloat(document.getElementById('ob-cpu-thresh').value) || 75,
    mem_threshold: parseFloat(document.getElementById('ob-mem-thresh').value) || 80,
    alert_email: document.getElementById('ob-alert-email').value.trim() || null,
  };
  try {
    await onboardAccountAPI(formData);
    showToast('✓ Account onboarded!');
    resetOnboardForm();
  } catch (e) {
    showToast('⛔ ' + e.message, 'error');
  }
}
```

---

## 4. API Endpoints Summary

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/token` | — | Login, returns JWT |
| GET | `/auth/me` | JWT | Current user info |
| GET | `/accounts` | JWT | List all accounts + health |
| GET | `/accounts/{id}` | JWT | Account detail + services |
| GET | `/accounts/{id}/metrics/{svc}` | JWT | CloudWatch time series |
| GET | `/accounts/{id}/alarms` | JWT | Active alarms |
| GET | `/alarms` | JWT | All alarms across accounts |
| GET | `/accounts/{id}/costs` | JWT | Cost Explorer data |
| POST | `/admin/accounts/onboard` | Admin JWT | Register new account |
| DELETE | `/admin/accounts/{id}` | Admin JWT | Remove account |
| GET | `/admin/users` | Admin JWT | List users |
| POST | `/admin/users` | Admin JWT | Create user |
| DELETE | `/admin/users/{username}` | Admin JWT | Delete user |

---

## 5. Production Checklist

- [ ] Replace `SECRET_KEY` with a secret from AWS Secrets Manager
- [ ] Move `USERS_DB` to a real database (DynamoDB / RDS)
- [ ] Move `ONBOARDED_ACCOUNTS_DB` to DynamoDB
- [ ] Enable HTTPS (use an ALB or nginx in front of uvicorn)
- [ ] Tighten CORS `allow_origins` to your actual frontend domain
- [ ] Add SNS integration for alarm notifications
- [ ] Set up CloudWatch Agent on EC2s for memory metrics
- [ ] Consider caching CloudWatch responses (ElastiCache / Redis) to avoid API throttling