"""Benign traffic generator: realistic legitimate users of the lab target, through the proxy.

Deterministic (no LLM). Runs alongside the red agent so the live eval can show Jev tells
benign traffic apart from attacks under load. Every request here is benign by construction;
each simulated user sends from a distinct source IP in a benign pool (TEST-NET-2, disjoint
from the red agent's 10.13.37.7) so verdicts group by source.

The target's paths, parameter names and credentials are re-randomized on every boot (see
MUTATION.md), so nothing here is hard-coded. `discover()` learns the running instance the way
a new staff member would: open the portal, read the operator handbook, sign in, and follow
the links to the four internal tools. Users then hit those same tools the attacks target,
with ordinary input, which is what makes this a real discrimination test (Jev scores request
content only, never the source IP or session).

Usage:  python benign_agent.py --duration 60        # flow benign traffic for 60s
        python benign_agent.py --count 50           # send 50 journeys then stop
"""
import argparse
import os
import random
import re
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlencode

import httpx

PROXY = os.getenv("PROXY_URL", "http://localhost:8080")
BENIGN_POOL = os.getenv("BENIGN_POOL", "198.51.100")  # TEST-NET-2; red agent uses 10.13.37.7

NAMES = ["Alice", "Bob", "Carol", "Dave", "Erin", "John", "Priya", "Sam", "Okafor", "Lindqvist"]
HOSTS = ["127.0.0.1", "localhost"]
# Link text on the signed-in home page -> tool kind. Text is fixed; the hrefs are per instance.
TOOL_LINKS = {"record lookup": "lookup", "network diagnostics": "netcheck",
              "document viewer": "fileview", "staff directory": "search"}


class _Page(HTMLParser):
    """Collects links (href, text), form inputs and the form action from one page."""
    def __init__(self, html):
        super().__init__()
        self.links, self.inputs, self.action, self._href, self._text = [], [], None, None, []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a":
            self._href, self._text = a.get("href"), []
        elif tag == "form" and self.action is None:
            self.action = a.get("action")
        elif tag == "input":
            self.inputs.append({"type": (a.get("type") or "text").lower(), "name": a.get("name"),
                                "value": a.get("value") or ""})

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join("".join(self._text).split()).lower()))
            self._href = None

    def link(self, *needles):
        return next((h for h, t in self.links if any(n in t for n in needles)), None)

    def field(self, kind):
        return next((i["name"] for i in self.inputs if i["type"] == kind and i["name"]), None)

    def hidden(self):
        return {i["name"]: i["value"] for i in self.inputs if i["type"] == "hidden" and i["name"]}


@dataclass
class Site:
    """What one boot of the target looks like, learned by browsing it."""
    signin: str
    handbook: str
    user: str
    password: str
    user_field: str
    pass_field: str
    tools: dict = field(default_factory=dict)   # kind -> {"path", "param", "extra"}
    docs: list = field(default_factory=lambda: ["notice.txt"])

    def paths(self):
        return {"/", self.signin, self.handbook} | {t["path"] for t in self.tools.values()}


def _client(proxy, ip):
    return httpx.Client(base_url=proxy, headers={"X-Forwarded-For": ip},
                        follow_redirects=True, timeout=15)


def _sign_in(client, site):
    form = _Page(client.get(site.signin).text)
    data = {**form.hidden(), site.user_field: site.user, site.pass_field: site.password}
    r = client.post(site.signin, data=data)
    if r.status_code >= 400 or form.field("password") and _Page(r.text).field("password"):
        raise RuntimeError("sign-in failed with the handbook credentials")
    return r


def discover(proxy=PROXY, ip=f"{BENIGN_POOL}.250"):
    """Learn the running instance's routes, fields and demo credentials by browsing it."""
    with _client(proxy, ip) as c:
        home = _Page(c.get("/").text)
        signin, handbook = home.link("sign in"), home.link("handbook")
        if not signin or not handbook:
            raise RuntimeError(f"no sign-in or handbook link on {proxy}/; is it the Bastion lab target?")
        book = c.get(handbook).text
        creds = re.search(r"Operator ID:\s*<strong>(.*?)</strong>.*?Passphrase:\s*<strong>(.*?)</strong>", book, re.S)
        if not creds:
            raise RuntimeError("operator handbook does not list demo credentials")
        form = _Page(c.get(signin).text)
        site = Site(signin=signin, handbook=handbook,
                    user=creds.group(1), password=creds.group(2),
                    user_field=form.field("text"), pass_field=form.field("password"))
        if not site.user_field or not site.pass_field:
            raise RuntimeError("sign-in form has no operator or passphrase field")
        landing = _Page(_sign_in(c, site).text)
        for href, text in landing.links:
            kind = TOOL_LINKS.get(text)
            if not kind:
                continue
            html = c.get(href).text
            page = _Page(html)
            site.tools[kind] = {"path": page.action or href, "param": page.field("text"), "extra": page.hidden()}
            if kind == "fileview":
                listed = re.search(r"Available:\s*([^<]+)", html)
                if listed:
                    site.docs = [d.strip() for d in listed.group(1).split(",") if d.strip()]
        missing = set(TOOL_LINKS.values()) - set(site.tools)
        if missing:
            raise RuntimeError(f"signed in, but these tools were not linked: {sorted(missing)}")
        return site


def benign_requests(site):
    """One randomized benign session against `site`: list of (method, path, query, body).

    These are the benign twins of the attacks: the same four tools, with a record number,
    a loopback host, a published document and a staff name."""
    t = site.tools
    def use(kind, value):
        return ("GET", t[kind]["path"], urlencode({t[kind]["param"]: value, **t[kind]["extra"]}), "")
    reqs = [("GET", "/", "", ""),
            use("lookup", str(random.randint(1, 5))),
            use("netcheck", random.choice(HOSTS)),
            use("fileview", random.choice(site.docs)),
            use("search", random.choice(NAMES))]
    if random.random() < .3:
        reqs.append(("GET", site.handbook, "", ""))
    return reqs


def _send(client, method, path, query, body):
    try:
        client.request(method, f"{path}?{query}" if query else path, content=body or None)
        return 1
    except Exception:
        return 0


def journey(site, proxy, ip):
    """One benign user's session from source IP `ip`: sign in, then use the tools in a
    shuffled order. Returns the number of requests sent."""
    reqs = benign_requests(site)
    random.shuffle(reqs)
    with _client(proxy, ip) as client:
        try:
            _sign_in(client, site)
            sent = 2
        except Exception:
            sent = 0          # keep flowing: Jev scores content, not whether the session is valid
        return sent + sum(_send(client, *r) for r in reqs)


def run(duration=None, count=None, proxy=PROXY, delay=0.3, stop=None, site=None):
    """Flow benign traffic until `duration` seconds elapse or `count` journeys are sent
    (whichever is given). `stop` is an optional threading.Event for clean shutdown."""
    site = site or discover(proxy)
    sent = journeys = 0
    start = time.time()
    while not (stop is not None and stop.is_set()):
        if duration is not None and time.time() - start >= duration:
            break
        if count is not None and journeys >= count:
            break
        journeys += 1
        sent += journey(site, proxy, f"{BENIGN_POOL}.{(journeys % 249) + 1}")
        time.sleep(delay)
    return sent


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benign traffic generator for the Bastion lab target")
    parser.add_argument("--duration", type=float, help="seconds to run")
    parser.add_argument("--count", type=int, help="number of user journeys to send")
    parser.add_argument("--proxy", default=PROXY, help="proxy base URL")
    parser.add_argument("--delay", type=float, default=0.3, help="seconds between journeys")
    args = parser.parse_args()
    if args.duration is None and args.count is None:
        args.count = 10
    site = discover(args.proxy)
    print(f"target: {len(site.tools)} tools at {', '.join(t['path'] for t in site.tools.values())}")
    n = run(duration=args.duration, count=args.count, proxy=args.proxy, delay=args.delay, site=site)
    print(f"benign traffic: sent {n} requests via {args.proxy}")
