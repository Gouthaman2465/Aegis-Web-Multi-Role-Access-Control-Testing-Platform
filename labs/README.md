# Aegis-Web Labs

This directory contains test targets used to verify scanner accuracy against access-control flaws.

---

## 1. Deliberately Vulnerable Lab App (`labs/vulnerable_app`)

The vulnerable app is a deterministic Flask application running on port 5001. It implements standard authentication (cookie sessions and Bearer tokens) and serves as the ground-truth oracle for access-control testing.

### Starting the Lab App
```bash
python labs/vulnerable_app/app.py
```

### Pre-seeded Credentials
- **Alice**: `alice` / `alice-pass` (role: `user`, privilege: 10, order: 1)
- **Bob**: `bob` / `bob-pass` (role: `user`, privilege: 10, order: 2)
- **Admin**: `admin` / `admin-pass` (role: `admin`, privilege: 100, order: 3)

---

### Manual Verification Commands (`curl`)

#### 1. Horizontal Access (IDOR) on `/orders/1`
Bob can view Alice's order using his session cookie:
```bash
# Log in as Bob
curl -s -c /tmp/bob_cookie.txt -X POST http://127.0.0.1:5001/login \
  -d "username=bob&password=bob-pass"

# Bob accesses Alice's order (order_id 1) -> 200 OK (VULNERABLE)
curl -s -b /tmp/bob_cookie.txt http://127.0.0.1:5001/orders/1
```

#### 2. Ownership Protected API on `/api/orders/1`
Bob's Bearer token is rejected when accessing Alice's order:
```bash
# Bob exchanges cookie for Bearer token
BOB_TOKEN=$(curl -s -b /tmp/bob_cookie.txt http://127.0.0.1:5001/api/token | grep -o '"token":"[^"]*' | cut -d'"' -f4)

# Bob attempts to access Alice's order JSON -> 403 Forbidden (SECURE)
curl -s -i -H "Authorization: Bearer $BOB_TOKEN" http://127.0.0.1:5001/api/orders/1
```

#### 3. Unauthenticated Access on `/api/internal/config`
Accessible without any credentials:
```bash
curl -s http://127.0.0.1:5001/api/internal/config
```

#### 4. Vertical Access on `/admin/users`
Alice (regular user) can access the user directory:
```bash
# Log in as Alice
curl -s -c /tmp/alice_cookie.txt -X POST http://127.0.0.1:5001/login \
  -d "username=alice&password=alice-pass"

# Alice accesses admin user directory -> 200 OK (VULNERABLE)
curl -s -b /tmp/alice_cookie.txt http://127.0.0.1:5001/admin/users
```

#### 5. Role Protected Admin API on `/api/admin/stats`
Alice's Bearer token is rejected from the administrative statistics:
```bash
# Alice exchanges cookie for Bearer token
ALICE_TOKEN=$(curl -s -b /tmp/alice_cookie.txt http://127.0.0.1:5001/api/token | grep -o '"token":"[^"]*' | cut -d'"' -f4)

# Alice attempts to access admin stats -> 403 Forbidden (SECURE)
curl -s -i -H "Authorization: Bearer $ALICE_TOKEN" http://127.0.0.1:5001/api/admin/stats
```

---

## 2. OWASP Juice Shop (Optional Real-World Demo)

To run Juice Shop locally in Docker:
```bash
docker compose --profile labs up -d juice-shop
```
Juice Shop will be accessible at `http://localhost:3000`.

### Scan Setup in Aegis-Web:
1. Register two normal accounts in the Juice Shop UI (e.g., `user1@example.com` and `user2@example.com`).
2. In the Aegis dashboard, add target `http://localhost:3000`.
3. As platform admin, mark the target as **Lab**.
4. Add two test accounts with identical privilege level (e.g. 10):
   - **Login URL**: `http://localhost:3000/#/login`
   - **Username selector**: `#email`
   - **Password selector**: `#password`
   - **Submit selector**: `#loginButton`
   - **Dismiss selectors**: `button[aria-label="Close Welcome Banner"]`, `a[aria-label="dismiss cookie message"]`
   - **Seed paths**: `/#/basket`
5. Start the scan.

*Note*: OWASP Juice Shop is a Single-Page Application (SPA). Discovery depends on crawl coverage, and SPA route states may vary. Findings in Juice Shop demonstrate real-world utility, but are not guaranteed across all versions.
