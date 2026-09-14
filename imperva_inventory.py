#!/usr/bin/env python3
"""
imperva_inventory.py - inventory Imperva Cloud WAF (Incapsula) sites into a CSV.

Walks the parent account and every sub-account, lists each onboarded site, and
records its security posture: WAF rule actions, ACLs, attached policies, and
optionally custom (Incap) rules.

Credentials come from the environment (create them in the Imperva console under
Account Management -> API Keys):

    export IMPERVA_API_ID=12345
    export IMPERVA_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

Usage:
    python3 imperva_inventory.py --verify                 # check creds, print account
    python3 imperva_inventory.py -o sites.csv             # full inventory
    python3 imperva_inventory.py -o sites.csv --account-id 12345
    python3 imperva_inventory.py -o sites.csv --no-policies
    python3 imperva_inventory.py -o sites.csv --include-rules --json raw.json

Zero dependencies: Python 3.7+ standard library only. Honours HTTPS_PROXY.
"""

import argparse
import csv
import getpass
import json
import os
import random
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

V1_BASE = "https://my.imperva.com/api/prov/v1"
V2_BASE = "https://api.imperva.com"

USER_AGENT = "imperva-inventory/1.0 (+python-urllib)"

# WAF threat rules returned in site["security"]["waf"]["rules"] -> CSV column.
WAF_RULES = {
    "api.threats.sql_injection": "waf_sql_injection",
    "api.threats.cross_site_scripting": "waf_cross_site_scripting",
    "api.threats.illegal_resource_access": "waf_illegal_resource_access",
    "api.threats.remote_file_inclusion": "waf_remote_file_inclusion",
    "api.threats.backdoor": "waf_backdoor",
    "api.threats.bot_access_control": "waf_bot_access_control",
    "api.threats.ddos": "waf_ddos",
}

# ACL rules returned in site["security"]["acls"]["rules"] -> CSV column.
ACL_RULES = {
    "api.acl.blacklisted_countries": "acl_blacklisted_countries",
    "api.acl.blacklisted_ips": "acl_blacklisted_ips",
    "api.acl.blacklisted_urls": "acl_blacklisted_urls",
    "api.acl.whitelisted_ips": "acl_whitelisted_ips",
}

COLUMNS = [
    "account_id",
    "account_name",
    "account_level",
    "account_parent_id",
    "site_id",
    "domain",
    "display_name",
    "site_status",
    "site_creation_date",
    "acceleration_level",
    "log_level",
    "ips",
    "cname",
    "origin_dns",
    "ssl_custom_certificate",
    "ssl_generated_certificate",
    "ssl_origin_tls",
] + list(WAF_RULES.values()) + [
    "ddos_activation_mode",
    "ddos_traffic_threshold",
] + list(ACL_RULES.values()) + [
    "login_protect_enabled",
    "incap_rules_count",
    "incap_rules",
    "policy_count",
    "policies",
    "policy_types",
    "notes",
]


class ImpervaError(Exception):
    """An API call returned a transport error or a non-zero `res` code."""


# --------------------------------------------------------------------------
# HTTP plumbing
# --------------------------------------------------------------------------

class Client:
    def __init__(self, api_id, api_key, rpm=40, retries=5, timeout=60,
                 insecure=False, verbose=False):
        self.api_id = api_id
        self.api_key = api_key
        self.retries = retries
        self.timeout = timeout
        self.verbose = verbose
        self.calls = 0
        self._min_interval = 60.0 / rpm if rpm > 0 else 0.0
        self._last_call = 0.0

        handlers = []
        if insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        # ProxyHandler is installed by default and reads HTTPS_PROXY/NO_PROXY.
        self._opener = urllib.request.build_opener(*handlers)

    def _throttle(self):
        if not self._min_interval:
            return
        elapsed = time.monotonic() - self._last_call
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_call = time.monotonic()

    def _request(self, method, url, data=None, headers=None):
        """Perform one HTTP call with throttling + backoff. Returns parsed JSON."""
        body = urllib.parse.urlencode(data).encode() if data else None
        hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if body:
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        hdrs.update(headers or {})

        last_error = None
        for attempt in range(self.retries):
            self._throttle()
            self.calls += 1
            req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
            try:
                with self._opener.open(req, timeout=self.timeout) as resp:
                    raw = resp.read().decode("utf-8", "replace")
                if self.verbose:
                    sys.stderr.write("  %s %s -> 200 (%d bytes)\n" % (method, url, len(raw)))
                return json.loads(raw) if raw.strip() else {}
            except urllib.error.HTTPError as exc:
                raw = exc.read().decode("utf-8", "replace")
                # Retry on throttling and transient server errors only.
                if exc.code in (429, 500, 502, 503, 504):
                    last_error = ImpervaError("HTTP %s from %s: %s" % (exc.code, url, raw[:300]))
                    self._backoff(attempt, exc.code, exc.headers.get("Retry-After"))
                    continue
                # 4xx bodies usually carry a useful JSON error - surface it.
                raise ImpervaError("HTTP %s from %s: %s" % (exc.code, url, raw[:500]))
            except urllib.error.URLError as exc:
                last_error = ImpervaError("network error calling %s: %s" % (url, exc.reason))
                self._backoff(attempt, "network", None)
            except json.JSONDecodeError:
                raise ImpervaError("non-JSON response from %s: %s" % (url, raw[:300]))
        raise last_error or ImpervaError("giving up on %s" % url)

    def _backoff(self, attempt, why, retry_after):
        if retry_after:
            try:
                delay = float(retry_after)
            except ValueError:
                delay = 2 ** attempt
        else:
            delay = (2 ** attempt) + random.uniform(0, 1)
        sys.stderr.write("  retrying after %s (attempt %d, wait %.1fs)\n"
                         % (why, attempt + 1, delay))
        time.sleep(delay)

    def v1(self, path, **params):
        """POST to the v1 management API. Raises on a non-zero `res` code.

        v1 signals application errors with HTTP 200 and res != 0, so the status
        code alone is never enough to tell success from failure.
        """
        data = {"api_id": self.api_id, "api_key": self.api_key}
        data.update({k: v for k, v in params.items() if v is not None})
        payload = self._request("POST", V1_BASE + path, data=data)
        res = str(payload.get("res", "0"))
        if res != "0":
            raise ImpervaError("%s -> res=%s %s"
                               % (path, res, payload.get("res_message", "")))
        return payload

    def v2(self, path, **params):
        """GET from the v2 API (api.imperva.com), which uses header auth."""
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        url = V2_BASE + path + ("?" + query if query else "")
        headers = {"x-API-Id": self.api_id, "x-API-Key": self.api_key}
        return self._request("GET", url, headers=headers)


# --------------------------------------------------------------------------
# API wrappers
# --------------------------------------------------------------------------

def whoami(client):
    """Account the API key itself belongs to."""
    return client.v1("/account").get("account", {})


def list_sub_accounts(client, parent_id=None, page_size=50):
    """Every sub-account under `parent_id` (defaults to the key's own account)."""
    out = []
    page = 0
    while True:
        payload = client.v1("/accounts/listSubAccounts", account_id=parent_id,
                            page_size=page_size, page_num=page)
        batch = payload.get("resultList") or []
        for sub in batch:
            out.append({
                "account_id": sub.get("sub_account_id"),
                "account_name": sub.get("sub_account_name") or "",
                "parent_id": sub.get("parent_id") or parent_id or "",
                "level": "sub",
            })
        if len(batch) < page_size:
            return out
        page += 1


def list_sites(client, account_id=None, page_size=50):
    """Every site in one account. `security` comes back inline - no extra calls."""
    out = []
    page = 0
    while True:
        payload = client.v1("/sites/list", account_id=account_id,
                            page_size=page_size, page_num=page)
        batch = payload.get("sites") or []
        out.extend(batch)
        if len(batch) < page_size:
            return out
        page += 1


def list_incap_rules(client, site_id):
    """Custom security/delivery rules on a site (one call per site - opt in)."""
    payload = client.v1("/sites/incapRules/list", site_id=site_id,
                        include_ad_rules="No", include_incap_rules="Yes")
    rules = payload.get("incap_rules") or {}
    if isinstance(rules, dict):
        flat = []
        for bucket in rules.values():
            if isinstance(bucket, list):
                flat.extend(bucket)
        return flat
    return rules if isinstance(rules, list) else []


def policies_by_site(client, account_id):
    """Map site_id -> [policy, ...] using one extended policy listing per account.

    The extended form of each policy carries the assets it is applied to, so a
    single call replaces one call per site.
    """
    payload = client.v2("/policies/v2/policies", extended="true", caid=account_id)
    policies = payload.get("value")
    if policies is None:
        policies = payload.get("data") if isinstance(payload.get("data"), list) else payload
    if not isinstance(policies, list):
        raise ImpervaError("unexpected policies payload: %s" % str(payload)[:300])

    mapping = {}
    for policy in policies:
        if not isinstance(policy, dict):
            continue
        for asset in policy.get("assets") or []:
            if not isinstance(asset, dict):
                continue
            asset_type = str(asset.get("assetType", "")).upper()
            if asset_type not in ("SITE", "WEBSITE", "1", ""):
                continue
            site_id = asset.get("assetId")
            if site_id is None:
                continue
            mapping.setdefault(str(site_id), []).append(policy)
    return mapping


# --------------------------------------------------------------------------
# Flattening
# --------------------------------------------------------------------------

def epoch_ms_to_iso(value):
    try:
        ms = int(value)
    except (TypeError, ValueError):
        return ""
    if ms <= 0:
        return ""
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def short_action(action):
    """'api.threats.action.block_request' -> 'block_request'."""
    if not action:
        return ""
    return str(action).rsplit(".", 1)[-1]


def join(values, sep="; "):
    return sep.join(str(v) for v in values if v not in (None, ""))


def dns_targets(records):
    """Pull the values a DNS record points at, e.g. the incapdns.net CNAME."""
    out = []
    for record in records or []:
        if not isinstance(record, dict):
            continue
        for target in record.get("set_data_to") or []:
            if target:
                out.append(str(target))
    return out


def flatten_url(entry):
    """ACL URL entries are {"value": "/admin", "pattern": "prefix"} dicts."""
    if not isinstance(entry, dict):
        return entry
    value = entry.get("value") or entry.get("url") or ""
    pattern = entry.get("pattern")
    return "%s (%s)" % (value, pattern) if pattern else value


def flatten_site(site, account, policies, incap_rules, notes):
    row = dict.fromkeys(COLUMNS, "")
    row["account_id"] = account.get("account_id", "")
    row["account_name"] = account.get("account_name", "")
    row["account_level"] = account.get("level", "")
    row["account_parent_id"] = account.get("parent_id", "")

    row["site_id"] = site.get("site_id", "")
    row["domain"] = site.get("domain", "")
    row["display_name"] = site.get("display_name") or site.get("domain", "")
    row["site_status"] = site.get("status", "")
    row["site_creation_date"] = epoch_ms_to_iso(site.get("site_creation_date"))
    row["acceleration_level"] = site.get("acceleration_level", "")
    row["log_level"] = site.get("log_level", "")
    row["ips"] = join(site.get("ips") or [])
    row["cname"] = join(dns_targets(site.get("dns")))
    row["origin_dns"] = join(dns_targets(site.get("original_dns")))

    ssl_info = site.get("ssl") or {}
    custom = ssl_info.get("custom_certificate") or {}
    generated = ssl_info.get("generated_certificate") or {}
    origin = ssl_info.get("origin_server") or {}
    row["ssl_custom_certificate"] = "yes" if custom.get("active") else "no"
    row["ssl_generated_certificate"] = generated.get("validation_method") or (
        "yes" if generated else "no")
    row["ssl_origin_tls"] = "yes" if origin.get("detected") or origin.get("enabled") else "no"

    security = site.get("security") or {}
    for rule in (security.get("waf") or {}).get("rules") or []:
        column = WAF_RULES.get(rule.get("id"))
        if not column:
            continue
        if rule.get("id") == "api.threats.bot_access_control":
            # Bot control reports two booleans instead of a single action.
            row[column] = join([
                "block_bad_bots" if rule.get("block_bad_bots") else "",
                "challenge_suspected_bots" if rule.get("challenge_suspected_bots") else "",
            ]) or "off"
        elif rule.get("id") == "api.threats.ddos":
            row[column] = short_action(rule.get("action")) or rule.get("activation_mode", "")
            row["ddos_activation_mode"] = short_action(rule.get("activation_mode"))
            row["ddos_traffic_threshold"] = rule.get("ddos_traffic_threshold", "")
        else:
            row[column] = short_action(rule.get("action"))

    for rule in (security.get("acls") or {}).get("rules") or []:
        column = ACL_RULES.get(rule.get("id"))
        if not column:
            continue
        values = (rule.get("countries") or rule.get("ips")
                  or rule.get("urls") or rule.get("geo") or [])
        if isinstance(values, dict):
            values = values.get("countries") or values.get("continents") or []
        if rule.get("id") == "api.acl.blacklisted_urls":
            values = [flatten_url(u) for u in values]
        row[column] = join(values, ",") or ""

    login_protect = site.get("login_protect") or {}
    row["login_protect_enabled"] = "yes" if login_protect.get("enabled") else "no"

    if incap_rules is not None:
        row["incap_rules_count"] = len(incap_rules)
        row["incap_rules"] = join(
            "%s [%s]" % (r.get("name", "?"), r.get("action", r.get("enabled", "")))
            for r in incap_rules if isinstance(r, dict)
        )

    if policies is not None:
        row["policy_count"] = len(policies)
        row["policies"] = join(p.get("name", p.get("id", "?")) for p in policies)
        row["policy_types"] = join(sorted({str(p.get("policyType", "")) for p in policies
                                           if p.get("policyType")}), ",")

    row["notes"] = join(notes)
    return row


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def build_account_list(client, args):
    if args.account_id:
        name = ""
        try:
            info = whoami(client)
            if str(info.get("account_id")) == str(args.account_id):
                name = info.get("account_name", "")
        except ImpervaError:
            pass
        return [{"account_id": args.account_id, "account_name": name,
                 "parent_id": "", "level": "requested"}]

    me = whoami(client)
    parent_id = me.get("account_id")
    accounts = []
    if not args.sub_accounts_only:
        accounts.append({
            "account_id": parent_id,
            "account_name": me.get("account_name", ""),
            "parent_id": me.get("parent_id", ""),
            "level": "parent",
        })

    try:
        subs = list_sub_accounts(client, parent_id, page_size=args.page_size)
        accounts.extend(subs)
        sys.stderr.write("Found %d sub-account(s) under %s (%s)\n"
                         % (len(subs), parent_id, me.get("account_name", "")))
    except ImpervaError as exc:
        sys.stderr.write("WARNING: could not list sub-accounts (%s).\n"
                         "         Continuing with the parent account only - this is "
                         "expected if the key is not a reseller/parent key.\n" % exc)
    return accounts


# --------------------------------------------------------------------------
# Interactive setup
# --------------------------------------------------------------------------

CONFIG_PATH = os.path.expanduser("~/.imperva_inventory.json")


def is_tty():
    return sys.stdin.isatty() and sys.stderr.isatty()


def say(text=""):
    """Prompts and progress go to stderr so stdout stays pipe-clean."""
    sys.stderr.write(text + "\n")
    sys.stderr.flush()


def ask(text, default=None):
    suffix = " [%s]: " % default if default else ": "
    sys.stderr.write(text + suffix)
    sys.stderr.flush()
    try:
        answer = input().strip()
    except EOFError:
        raise KeyboardInterrupt
    return answer or (default or "")


def ask_yes_no(text, default=True):
    hint = "Y/n" if default else "y/N"
    while True:
        sys.stderr.write("%s [%s]: " % (text, hint))
        sys.stderr.flush()
        try:
            answer = input().strip().lower()
        except EOFError:
            raise KeyboardInterrupt
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        say("  Please answer y or n.")


def ask_choice(text, options, default=1):
    """options: list of (label, value). Returns the chosen value."""
    say(text)
    for index, (label, _) in enumerate(options, 1):
        marker = " (default)" if index == default else ""
        say("  [%d] %s%s" % (index, label, marker))
    while True:
        answer = ask("Choose", str(default))
        try:
            index = int(answer)
        except ValueError:
            say("  Enter a number between 1 and %d." % len(options))
            continue
        if 1 <= index <= len(options):
            return options[index - 1][1]
        say("  Enter a number between 1 and %d." % len(options))


def load_saved_credentials():
    try:
        with open(CONFIG_PATH) as handle:
            data = json.load(handle)
        return data.get("api_id"), data.get("api_key")
    except (OSError, ValueError):
        return None, None


def save_credentials(api_id, api_key):
    """Write 0600 so the key is not world-readable."""
    try:
        fd = os.open(CONFIG_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump({"api_id": api_id, "api_key": api_key}, handle, indent=2)
        os.chmod(CONFIG_PATH, 0o600)
        say("  Saved to %s (permissions 0600)." % CONFIG_PATH)
    except OSError as exc:
        say("  Could not save credentials: %s" % exc)


def resolve_credentials(args, allow_prompt):
    """Env vars win, then the saved config file, then an interactive prompt."""
    api_id = os.environ.get("IMPERVA_API_ID")
    api_key = os.environ.get("IMPERVA_API_KEY")
    source = "environment"

    if not (api_id and api_key):
        api_id, api_key = load_saved_credentials()
        source = CONFIG_PATH
    if not (api_id and api_key):
        if not allow_prompt:
            return None, None, None
        api_id, api_key = None, None
        source = "prompt"

    return api_id, api_key, source


def make_client(api_id, api_key, args):
    return Client(api_id, api_key, rpm=args.rpm, retries=args.retries,
                  timeout=args.timeout, insecure=args.insecure, verbose=args.verbose)


def prompt_for_credentials(args):
    """Ask for an API ID/key and keep asking until they actually authenticate."""
    while True:
        api_id = ask("  API ID")
        if not api_id:
            say("  An API ID is required.")
            continue
        try:
            api_key = getpass.getpass("  API Key (hidden): ").strip()
        except EOFError:
            raise KeyboardInterrupt
        if not api_key:
            say("  An API key is required.")
            continue

        client = make_client(api_id, api_key, args)
        say("  Checking credentials...")
        try:
            info = whoami(client)
        except ImpervaError as exc:
            say("  Rejected: %s" % exc)
            if not ask_yes_no("  Try again?", True):
                raise KeyboardInterrupt
            continue
        return api_id, api_key, client, info


def show_account(info):
    say()
    say("  Authenticated.")
    say("    Account : %s (%s)" % (info.get("account_name", "?"), info.get("account_id")))
    say("    Plan    : %s" % (info.get("plan_name") or "n/a"))
    say()


def interactive_setup(args):
    """Full guided setup. Returns (client, account_info) or raises KeyboardInterrupt."""
    say()
    say("=" * 62)
    say("  Imperva Cloud WAF - Site Inventory")
    say("=" * 62)
    say()

    # --- Credentials -----------------------------------------------------
    api_id, api_key, source = resolve_credentials(args, allow_prompt=True)
    client = info = None

    if api_id and api_key:
        say("Found credentials in %s (API ID %s)." % (source, api_id))
        if ask_yes_no("Use them?", True):
            client = make_client(api_id, api_key, args)
            say("  Checking credentials...")
            try:
                info = whoami(client)
            except ImpervaError as exc:
                say("  Rejected: %s" % exc)
                client = info = None
        else:
            client = info = None

    if client is None:
        say()
        say("Create an API key in the Imperva console under")
        say("Account Management -> API Keys. Use a key on the PARENT account")
        say("so it can enumerate sub-accounts.")
        api_id, api_key, client, info = prompt_for_credentials(args)
        show_account(info)
        # Confirm the key works before offering to persist it.
        if ask_yes_no("Save these credentials to %s for next time?" % CONFIG_PATH, False):
            save_credentials(api_id, api_key)
    else:
        show_account(info)

    # --- Scope -----------------------------------------------------------
    scope = ask_choice("What do you want to inventory?", [
        ("Everything - this account plus all sub-accounts", "all"),
        ("Sub-accounts only (skip sites owned by the parent)", "subs"),
        ("A single account", "one"),
    ], default=1)

    args.sub_accounts_only = (scope == "subs")
    args.account_id = None

    if scope == "one":
        say()
        say("  Looking up sub-accounts...")
        try:
            subs = list_sub_accounts(client, info.get("account_id"), page_size=args.page_size)
        except ImpervaError as exc:
            say("  Could not list sub-accounts: %s" % exc)
            subs = []
        options = [("%s (%s) - this account" % (info.get("account_name", "?"),
                                                info.get("account_id")),
                    info.get("account_id"))]
        options += [("%s (%s)" % (s["account_name"] or "unnamed", s["account_id"]),
                     s["account_id"]) for s in subs]
        if len(options) == 1:
            say("  No sub-accounts visible; using this account.")
            args.account_id = info.get("account_id")
        else:
            args.account_id = ask_choice("Which account?", options, default=1)

    # --- What to collect -------------------------------------------------
    say()
    args.no_policies = not ask_yes_no(
        "Include attached policies? (recommended)", True)
    args.include_rules = ask_yes_no(
        "Include custom Incap rules? (slower - one API call per site)", False)

    # --- Output ----------------------------------------------------------
    say()
    args.output = ask("Output CSV file", args.output)
    if os.path.exists(args.output):
        if not ask_yes_no("  %s exists. Overwrite?" % args.output, True):
            args.output = ask("  New filename", "imperva_sites_new.csv")
    if ask_yes_no("Also save the raw API responses as JSON? (useful for debugging)", False):
        args.json_output = ask("  JSON file", "imperva_raw.json")

    # --- Confirm ---------------------------------------------------------
    scope_text = {
        "all": "parent account + all sub-accounts",
        "subs": "sub-accounts only",
        "one": "account %s only" % args.account_id,
    }[scope]
    say()
    say("-" * 62)
    say("  Scope    : %s" % scope_text)
    say("  Policies : %s" % ("no" if args.no_policies else "yes"))
    say("  Rules    : %s" % ("yes (slower)" if args.include_rules else "no"))
    say("  Output   : %s%s" % (args.output,
                               " (+ %s)" % args.json_output if args.json_output else ""))
    say("  Throttle : %s" % ("%d calls/min" % args.rpm if args.rpm else "unlimited"))
    say("-" * 62)
    say()
    if not ask_yes_no("Start the inventory?", True):
        raise KeyboardInterrupt
    say()
    return client, info


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Inventory Imperva Cloud WAF sites across all sub-accounts into a CSV.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run with no arguments for a guided, interactive setup.",
    )
    parser.add_argument("-i", "--interactive", action="store_true",
                        help="force the guided setup even when flags are given")
    parser.add_argument("--non-interactive", action="store_true",
                        help="never prompt; fail if credentials are missing (for cron/CI)")
    parser.add_argument("-o", "--output", default="imperva_sites.csv",
                        help="CSV output path (default: imperva_sites.csv)")
    parser.add_argument("--json", dest="json_output",
                        help="also write the raw API payloads to this JSON file")
    parser.add_argument("--account-id", help="inventory only this account id")
    parser.add_argument("--sub-accounts-only", action="store_true",
                        help="skip sites owned directly by the parent account")
    parser.add_argument("--no-policies", action="store_true",
                        help="skip the v2 Policy Management lookups")
    parser.add_argument("--include-rules", action="store_true",
                        help="also fetch custom Incap rules (one extra API call per site)")
    parser.add_argument("--page-size", type=int, default=50,
                        help="API page size, max 100 (default: 50)")
    parser.add_argument("--rpm", type=int, default=40,
                        help="max API calls per minute; 0 disables throttling (default: 40)")
    parser.add_argument("--timeout", type=int, default=60, help="per-request timeout in seconds")
    parser.add_argument("--retries", type=int, default=5, help="retries on 429/5xx/network errors")
    parser.add_argument("--insecure", action="store_true",
                        help="skip TLS verification (only for TLS-inspecting corporate proxies)")
    parser.add_argument("--verify", action="store_true",
                        help="validate credentials, print the account, and exit")
    parser.add_argument("-v", "--verbose", action="store_true", help="log every HTTP call")
    args = parser.parse_args(argv)

    # No flags at all on a terminal means the user wants the wizard.
    bare_invocation = not (argv if argv is not None else sys.argv[1:])
    wizard = (args.interactive or bare_invocation) and not args.non_interactive

    if wizard and not is_tty():
        if args.interactive:
            sys.stderr.write("--interactive needs a terminal; stdin is not a TTY.\n")
            return 1
        wizard = False

    client = None
    if wizard:
        client, _ = interactive_setup(args)
    else:
        api_id, api_key, _ = resolve_credentials(args, allow_prompt=False)
        if not (api_id and api_key):
            # Flags were given but credentials are missing - ask for just those.
            if is_tty() and not args.non_interactive:
                say("No credentials in IMPERVA_API_ID / IMPERVA_API_KEY or %s." % CONFIG_PATH)
                try:
                    api_id, api_key, client, _ = prompt_for_credentials(args)
                except KeyboardInterrupt:
                    say("\nCancelled.")
                    return 130
            else:
                parser.error("set IMPERVA_API_ID and IMPERVA_API_KEY, or run "
                             "without arguments for interactive setup")
        if client is None:
            client = make_client(api_id, api_key, args)

    if args.verify:
        try:
            info = whoami(client)
        except ImpervaError as exc:
            sys.stderr.write("Credential check FAILED: %s\n" % exc)
            return 1
        print("Credentials OK.")
        print("  account_id   : %s" % info.get("account_id"))
        print("  account_name : %s" % info.get("account_name"))
        print("  plan         : %s" % info.get("plan_name"))
        print("  parent_id    : %s" % (info.get("parent_id") or "(none - this is a top-level account)"))
        return 0

    start = time.time()
    accounts = build_account_list(client, args)
    rows = []
    raw = {"accounts": accounts, "sites": {}}
    failures = []

    for index, account in enumerate(accounts, 1):
        account_id = account["account_id"]
        label = "%s (%s)" % (account_id, account.get("account_name") or account["level"])
        sys.stderr.write("[%d/%d] account %s\n" % (index, len(accounts), label))

        try:
            sites = list_sites(client, account_id, page_size=args.page_size)
        except ImpervaError as exc:
            sys.stderr.write("  ERROR listing sites: %s\n" % exc)
            failures.append("account %s: %s" % (account_id, exc))
            continue

        policy_map = None
        policy_note = []
        if not args.no_policies:
            try:
                policy_map = policies_by_site(client, account_id)
            except ImpervaError as exc:
                sys.stderr.write("  WARNING policies unavailable: %s\n" % exc)
                policy_note = ["policies unavailable: %s" % str(exc)[:120]]

        sys.stderr.write("  %d site(s)\n" % len(sites))
        raw["sites"][str(account_id)] = sites

        for site in sites:
            notes = list(policy_note)
            incap = None
            if args.include_rules:
                try:
                    incap = list_incap_rules(client, site.get("site_id"))
                except ImpervaError as exc:
                    notes.append("incap rules unavailable: %s" % str(exc)[:120])
            policies = None
            if policy_map is not None:
                policies = policy_map.get(str(site.get("site_id")), [])
            rows.append(flatten_site(site, account, policies, incap, notes))

    rows.sort(key=lambda r: (str(r["account_name"]).lower(), str(r["domain"]).lower()))

    with open(args.output, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as handle:
            json.dump(raw, handle, indent=2, sort_keys=True)

    sys.stderr.write("\nWrote %d site(s) from %d account(s) to %s\n"
                     % (len(rows), len(accounts), args.output))
    sys.stderr.write("%d API call(s) in %.1fs\n" % (client.calls, time.time() - start))
    if failures:
        sys.stderr.write("%d account(s) failed:\n" % len(failures))
        for failure in failures:
            sys.stderr.write("  - %s\n" % failure)
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\nInterrupted.\n")
        sys.exit(130)
