# Imperva Cloud WAF — Site Inventory

Exports every onboarded site across your Imperva Cloud WAF (Incapsula) parent
account and all sub-accounts into a single CSV: the site, which sub-account owns
it, and exactly what protection is switched on.

Built for onboarding audits — answering "what have we actually got in Imperva,
and is it all protected the same way?"

- **No dependencies.** Python 3.7+ standard library only.
- **Read-only.** Every call is a `GET`/list operation; nothing is modified.
- **One row per site**, 37 columns, Excel-ready.

---

## Quick start

Run it with no arguments and it walks you through everything:

```sh
python3 imperva_inventory.py
```

```
==============================================================
  Imperva Cloud WAF - Site Inventory
==============================================================

Create an API key in the Imperva console under
Account Management -> API Keys. Use a key on the PARENT account
so it can enumerate sub-accounts.
  API ID: 12345
  API Key (hidden):
  Checking credentials...

  Authenticated.
    Account : Parent Corp (111)
    Plan    : Enterprise

Save these credentials to ~/.imperva_inventory.json for next time? [y/N]: y

What do you want to inventory?
  [1] Everything - this account plus all sub-accounts (default)
  [2] Sub-accounts only (skip sites owned by the parent)
  [3] A single account
Choose [1]: 1

Include attached policies? (recommended) [Y/n]: y
Include custom Incap rules? (slower - one API call per site) [y/N]: n

Output CSV file [imperva_sites.csv]:
Also save the raw API responses as JSON? (useful for debugging) [y/N]: n

--------------------------------------------------------------
  Scope    : parent account + all sub-accounts
  Policies : yes
  Rules    : no
  Output   : imperva_sites.csv
  Throttle : 40 calls/min
--------------------------------------------------------------

Start the inventory? [Y/n]: y

Found 12 sub-account(s) under 111 (Parent Corp)
[1/13] account 111 (Parent Corp)
  4 site(s)
...
Wrote 214 site(s) from 13 account(s) to imperva_sites.csv
31 API call(s) in 48.2s
```

The API key is typed hidden (never echoed, never in your shell history).
A wrong key is rejected immediately with a retry, rather than failing
halfway through the run.

Choosing **[3] A single account** shows a numbered menu of your sub-accounts
to pick from — no need to know account IDs.

### Where credentials come from

Checked in this order, first hit wins:

1. `IMPERVA_API_ID` / `IMPERVA_API_KEY` environment variables
2. `~/.imperva_inventory.json` — written only if you opt in, `chmod 0600`
3. An interactive prompt

To delete saved credentials: `rm ~/.imperva_inventory.json`

### Scripted / unattended use

Flags bypass the wizard entirely, so the same script works in cron or CI:

```sh
export IMPERVA_API_ID=12345
export IMPERVA_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

python3 imperva_inventory.py --verify                  # check creds, exit
python3 imperva_inventory.py -o sites.csv              # full inventory
python3 imperva_inventory.py -o sites.csv --non-interactive
```

Rules of thumb:

- **No arguments + a terminal** → full wizard.
- **Any flag given** → flags are used as-is; you are only prompted for
  credentials if they are missing (and only if you are on a terminal).
- **No terminal** (cron, CI, piped output) → never prompts. Missing
  credentials fail immediately with a clear message rather than hanging.
- `--non-interactive` guarantees that behaviour even on a terminal.
- `-i` / `--interactive` forces the wizard even when flags are given.

## Options

| Flag | Purpose |
|---|---|
| *(no flags)* | Guided interactive setup |
| `-i, --interactive` | Force the wizard even when other flags are given |
| `--non-interactive` | Never prompt; fail if credentials are missing (cron/CI) |
| `-o, --output PATH` | CSV path (default `imperva_sites.csv`) |
| `--verify` | Validate credentials, print the account, exit |
| `--account-id N` | Inventory one account only |
| `--sub-accounts-only` | Skip sites owned directly by the parent |
| `--no-policies` | Skip the v2 Policy Management lookups |
| `--include-rules` | Also list custom Incap rules — **one extra API call per site** |
| `--json raw.json` | Dump raw API payloads alongside the CSV |
| `--page-size N` | API page size, max 100 (default 50) |
| `--rpm N` | API calls per minute; `0` disables throttling (default 40) |
| `--timeout N` | Per-request timeout in seconds (default 60) |
| `--retries N` | Retries on 429/5xx/network errors (default 5) |
| `--insecure` | Skip TLS verification — only for TLS-inspecting corporate proxies |
| `-v, --verbose` | Log every HTTP call |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean run |
| `1` | Credential check failed |
| `2` | Partial — some accounts failed; the CSV still contains everything else |
| `130` | Interrupted (Ctrl-C) |

---

## CSV column reference

| Column | Description |
|---|---|
| `account_id` | Imperva account that owns the site |
| `account_name` | Sub-account name |
| `account_level` | `parent`, `sub`, or `requested` (with `--account-id`) |
| `account_parent_id` | Parent of that sub-account |
| `site_id` | Imperva site id — the stable key for joins |
| `domain` | Protected domain |
| `display_name` | Friendly name in the console; falls back to `domain` |
| `site_status` | e.g. `fully-configured`, `pending-dns-changes`, `bypassed` |
| `site_creation_date` | Onboarding date, `YYYY-MM-DD HH:MM:SS UTC` |
| `acceleration_level` | CDN/acceleration tier |
| `log_level` | SIEM log level — `full`, `security`, `none` |
| `ips` | Imperva-facing IPs (`; ` separated) |
| `cname` | The `*.incapdns.net` target DNS should point at |
| `origin_dns` | Origin server the site fronts |
| `ssl_custom_certificate` | `yes` / `no` — customer-uploaded cert active |
| `ssl_generated_certificate` | Validation method of the Imperva-generated cert |
| `ssl_origin_tls` | `yes` / `no` — TLS to origin detected/enabled |
| `waf_sql_injection` | Action: `block_request`, `alert`, `ignore`, `block_user`, `block_ip` |
| `waf_cross_site_scripting` | As above |
| `waf_illegal_resource_access` | As above |
| `waf_remote_file_inclusion` | As above |
| `waf_backdoor` | As above, plus `quarantine_url` |
| `waf_bot_access_control` | `block_bad_bots`, `challenge_suspected_bots`, both, or `off` |
| `waf_ddos` | DDoS action |
| `ddos_activation_mode` | `auto`, `on`, `off` |
| `ddos_traffic_threshold` | Requests/sec threshold that trips auto mode |
| `acl_blacklisted_countries` | Blocked country codes (comma separated) |
| `acl_blacklisted_ips` | Blocked IPs/CIDRs |
| `acl_blacklisted_urls` | Blocked URLs as `/path (pattern)` |
| `acl_whitelisted_ips` | Allow-listed IPs/CIDRs |
| `login_protect_enabled` | `yes` / `no` — two-factor login protection |
| `incap_rules_count` | Custom rule count (`--include-rules` only) |
| `incap_rules` | `Rule name [ACTION]`, `; ` separated (`--include-rules` only) |
| `policy_count` | Number of attached policies |
| `policies` | Policy names, `; ` separated |
| `policy_types` | Distinct policy types, e.g. `ACL,WAF_RULES` |
| `notes` | Per-site warnings, e.g. a policy lookup that failed |

Empty cells mean Imperva did not return that setting for the site — not that the
feature is off. `notes` will explain when a lookup failed outright.

---

## Audit recipes

Once you have `sites.csv`, the questions an onboarding audit usually asks.
All of these use a CSV parser rather than `awk -F,` / `grep` on purpose: fields
like `display_name` and the ACL lists legitimately contain commas, and splitting
on commas silently drops those rows.

```sh
# Sites in alert-only mode for SQLi - protection on paper, not in practice
python3 -c "
import csv
for r in csv.DictReader(open('sites.csv', encoding='utf-8-sig')):
    if r['waf_sql_injection'] == 'alert':
        print(r['account_name'], r['domain'])
"

# Sites with no policies attached at all
python3 -c "
import csv
for r in csv.DictReader(open('sites.csv', encoding='utf-8-sig')):
    if r['policy_count'] in ('0', ''):
        print(r['account_name'], r['domain'])
"

# Site count per sub-account
python3 -c "
import csv, collections
c = collections.Counter(r['account_name'] for r in
    csv.DictReader(open('sites.csv', encoding='utf-8-sig')))
for name, n in c.most_common(): print('%5d  %s' % (n, name))
"

# Sites not fully onboarded (DNS never cut over)
python3 -c "
import csv
for r in csv.DictReader(open('sites.csv', encoding='utf-8-sig')):
    if r['site_status'] != 'fully-configured':
        print('%-40s %-20s %s' % (r['domain'], r['site_status'], r['account_name']))
"

# Any site whose WAF posture differs from your standard - the real audit question
python3 -c "
import csv
STANDARD = {'waf_sql_injection': 'block_request',
            'waf_cross_site_scripting': 'block_request',
            'waf_remote_file_inclusion': 'block_request'}
for r in csv.DictReader(open('sites.csv', encoding='utf-8-sig')):
    drift = {k: r[k] for k, v in STANDARD.items() if r[k] != v}
    if drift:
        print('%-40s %s' % (r['domain'], drift))
"
```

## API endpoints used

| Purpose | Endpoint |
|---|---|
| Identify the key's account | `POST my.imperva.com/api/prov/v1/account` |
| List sub-accounts | `POST /api/prov/v1/accounts/listSubAccounts` |
| List sites (incl. inline WAF/ACL config) | `POST /api/prov/v1/sites/list` |
| Custom rules (optional) | `POST /api/prov/v1/sites/incapRules/list` |
| Attached policies | `GET api.imperva.com/policies/v2/policies?extended=true&caid=N` |

---

## Design notes

- **Call volume is kept low.** `sites/list` returns each site's WAF and ACL
  config inline, so there is no per-site security call. Policies are fetched
  once per account — the extended listing names the assets each policy is
  applied to — and inverted into a site→policies map rather than one call per
  site. A 200-site estate across 10 sub-accounts costs roughly 25 calls.
  `--include-rules` is the exception: it adds one call per site, so a 200-site
  estate jumps to ~225 calls and several minutes at the default rate limit.
- **v1 reports failures with HTTP 200.** Errors arrive as a non-zero `res` field
  in the body, so the client checks `res` rather than trusting the status code.
  This is the usual reason a hand-rolled script silently produces an empty CSV.
- **Throttled and retried.** Calls are paced (default 40/min) with exponential
  backoff and jitter on 429/5xx, honouring `Retry-After`.
- **Partial failure is not total failure.** An account that errors is logged and
  skipped; everything else still exports and the run ends with exit code `2` and
  a summary of what failed.
- **Proxy aware.** `urllib` picks up `HTTPS_PROXY` / `NO_PROXY` automatically.
- CSV is written UTF-8 **with BOM** so Excel opens it without mangling
  non-ASCII domain names.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Script hangs waiting for input in cron | It found a TTY. Add `--non-interactive`. |
| Want to change a saved key | `rm ~/.imperva_inventory.json`, then rerun. |
| `Credential check FAILED` | Wrong `IMPERVA_API_ID` / `IMPERVA_API_KEY`, or the key is disabled. Confirm in **Account Management → API Keys**. |
| `WARNING: could not list sub-accounts` | The key is on a normal account, not a parent/reseller account. Expected — the run continues against that one account. |
| `res=9403 Unknown/unauthorized account_id` | The key cannot read that sub-account. Use a parent-account key, or scope with `--account-id`. |
| Policy columns empty, `notes` says *policies unavailable* | The v2 Policy Management API is unreachable or shaped differently on your tenant — see the caveat below. Everything else still exports; `--no-policies` silences it. |
| `CERTIFICATE_VERIFY_FAILED` | TLS-inspecting corporate proxy. Point `SSL_CERT_FILE` at your corporate CA bundle, or use `--insecure`. |
| Frequent `retrying after 429` | Lower `--rpm` (try `20`). |
| Run is very slow | Drop `--include-rules`; it is one call per site. |
| Excel mangles accented domains | Open via **Data → From Text/CSV** and pick UTF-8; the BOM should make this automatic. |

---

## Status / caveats

The data-shaping logic is tested end to end against stubbed API responses —
pagination, the sub-account walk, per-site policy attribution, and the
non-zero-`res` failure path all behave correctly.

**Not yet validated against a live Imperva tenant.** The endpoint shapes come
from Imperva's documented API. The least certain is the v2 policies call
(`/policies/v2/policies?extended=true&caid=N`) — specifically whether the
extended listing includes the `assets` array the site→policy mapping depends on.
If it differs, it fails soft: policy columns come back empty with an explanation
in `notes` and every other column still exports.

First real run, use:

```sh
python3 imperva_inventory.py --account-id <one-account> -v --json raw.json -o test.csv
```

`raw.json` holds the unmodified payloads, so any field-name differences on your
tenant are easy to spot and correct.
