I couldn't run my probe script because the command wasn't approved. Every finding below comes from reading the code and from how CPython's `urllib.parse` and `ipaddress` behave. Items marked **(verify)** depend on the third-party APIs' behavior and should be confirmed against the vendor docs. I didn't modify any files.

## Critical

1. **`src/chc/reputation.py:138-139` — critical — The `commercial_ok` gating can be bypassed completely.** `ReputationService(feeds=...)` takes any iterable of feeds and never checks `commercial_ok` or the tier. Gating only happens in `FeedIngestor.enable()`, and nothing forces callers to go through it. `ReputationService(feeds=[VirusTotalPublicFeed()])` will query a non-commercial feed in production. So yes, a non-commercial feed can be used, which breaks the rule in architecture §6 and §10.2. The tests themselves pass raw feed lists in (`tests/test_reputation.py:30`).

2. **`src/chc/reputation.py:155-157` — critical — One failing feed fails the whole check.** `f.lookup()` runs with no `try/except`. Any feed exception (timeout, 4xx/5xx from `raise_for_status`, bad JSON, `AttributeError` from an odd payload) breaks the whole `check()` call. You get no verdict from the healthy feeds and nothing is cached. That contradicts the architecture's retry-safe, cache-absorbs-repeats design (§4, §10.3).

3. **`src/chc/reputation.py:156` + `src/chc/feeds/abuseipdb.py:21-22` — critical (combined with #2) — Feeds aren't routed by indicator kind.** Every feed is queried for every kind. AbuseIPDB gets URLs and domains as `ipAddress`, and its API rejects those with a 422 **(verify)**. `raise_for_status` then raises. With the three feeds in the architecture doc, every `check-url` and `check-domain` call would fail. The `ThreatFeed` protocol (`base.py:19-26`) has no way for a feed to say which kinds it supports.

## High

4. **`src/chc/feeds/misp.py:24-26` — high — MISP returns "malicious" for almost any response.** `attributes/restSearch` returns `{"response": {"Attribute": [...]}}`, a dict. `{"Attribute": []}` is truthy, so `if response:` reports malicious even when nothing matched. The verdict is also always category `"c2"` at confidence 0.8, ignoring `to_ids`, the attribute category, and the event threat level.

5. **`src/chc/feeds/misp.py:21` — high (verify) — MISP filters probably aren't applied.** MISP's `restSearch` expects a POST with a JSON body. A GET with query-string `value`/`type` is likely ignored. That could return unfiltered attributes, which is a false positive on every call and a heavy load on the MISP server.

6. **`src/chc/feeds/phishtank.py:22` — high (verify) — The PhishTank response fields look wrong.** The real API returns `results.in_database`, `results.verified` and `results.valid`. There is no `in_db` key, so every lookup returns "clean". Also, `verified` only means "someone reviewed it"; `valid` is what says it's phishing. Even with the key name fixed, a URL that was verified as *not* phishing would be flagged malicious.

7. **`src/chc/reputation.py:38-42` — high — Other IPv4 spellings get past the guard.** `ipaddress.ip_address` only parses strict dotted-quad, so anything else is treated as a DNS name and allowed. That covers `http://2130706433/`, `http://0x7f.0.0.1/`, `http://0177.0.0.1/` and `http://127.1/`, and probably fullwidth digits like `１２７.0.0.1` too. All of these reach 127.0.0.1 through `inet_aton` or IDNA. The same gap exists in `normalize_domain` (`:91`).

8. **`src/chc/reputation.py:18-29,42` — high — IPv6-embedded IPv4 gets past the guard.** `ip in net` is always False when the IP versions differ. So `[::ffff:127.0.0.1]`, `[::ffff:a9fe:a9fe]` (metadata), `[::127.0.0.1]`, `[64:ff9b::7f00:1]` (NAT64), `[2002:7f00:1::]` (6to4) and `[::]` (unspecified) are all accepted. The fix is to unwrap `ipv4_mapped`, `sixtofour` and `teredo`, then reject `not ip.is_global`.

9. **`src/chc/reputation.py:145-149` — high — With `kind=None` or `kind="ip"`, nothing is validated.** In both cases the raw indicator goes to every feed. `check("http://169.254.169.254/", None)` and `check("10.0.0.1", "ip")` are passed through untouched. There is no `normalize_ip`. Feeds also receive `"unknown"`, which isn't a valid `IndicatorKind`. `kind_of()` (`:96`) exists but is never used.

## Medium

10. **`src/chc/reputation.py:18-31` — medium — The denylist is incomplete.** It doesn't cover 192.0.0.0/24, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4, 255.255.255.255, TEST-NETs, ff00::/8, fec0::/10, 100::/64 or 2001:db8::/32. `_METADATA_IPS` is redundant (169.254/16 already covers it), and it misses `fd00:ec2::254`, though fc00::/7 happens to catch that one.

11. **`src/chc/reputation.py:41` — medium (high once anything fetches) — The guard never resolves DNS.** `localhost`, `metadata.google.internal`, `127.0.0.1.nip.io`, the trailing-dot form `127.0.0.1.`, and any attacker domain pointing at RFC1918 all pass. Privacy model §2.1 explicitly requires DNS resolution, yet the module docstring presents these helpers as the SSRF guard.

12. **`src/chc/reputation.py:68-70` — medium — IPv6 hosts are rebuilt without brackets.** `http://[2001:db8::1]:8080/x` becomes `http://2001:db8::1:8080/x`, which is malformed and ambiguous.

13. **`src/chc/reputation.py:83-84` — medium — `normalize_domain` returns the wrong host for IPv6 URLs, as a consequence of #12.** Re-parsing the unbracketed URL gives the wrong hostname: `https://[2606:4700::1]/` becomes `"2606"`. A mapped-address bypass like `https://[::ffff:127.0.0.1]/` becomes `""`. That empty string is then sent to feeds and cached.

14. **`src/chc/reputation.py:60-61` — medium — Python and browsers parse some URLs differently, which allows verdict evasion.** `urlsplit` doesn't treat `\` as a path separator, but WHATWG browsers do. `https://phish.example\@google.com/` normalizes to `https://google.com/`, while a browser goes to `phish.example`.

15. **`src/chc/reputation.py:67-73` — medium — Normalization isn't canonical, so cache keys and feed matches split.** A default port (`:443`) is kept. An empty path and `/` count as different URLs. The trailing-dot host isn't stripped. Percent-encoding isn't normalized, and IDN hosts aren't IDNA-encoded. One URL can therefore get several cache entries, and feeds may miss a match.

16. **`src/chc/reputation.py:71-73` — medium (privacy) — Query strings are kept.** Privacy model §1.1 says only "origin + path". Query strings often carry tokens and PII, and they get forwarded to third-party feeds (PhishTank, and AbuseIPDB because of #3) and cached.

17. **`src/chc/reputation.py:124` — medium — Unvalidated verdicts can crash the merge.** `_VERDICT_RANK[v.verdict]` raises `KeyError` for anything outside the four values (`"Malicious"`, `"bad"`). The `Literal` type isn't enforced at runtime. Confidence isn't checked either (NaN, values above 1, negatives, strings). The threat model says feed data is untrusted.

18. **`src/chc/feeds/phishtank.py:24`, `abuseipdb.py:29` vs `misp.py:27` — medium — "Not found" means different things in different feeds.** PhishTank says "clean" when a URL isn't in its database, and also when it is in the database but unverified (`:22`). MISP returns `None`. A lack of evidence ends up asserted as "clean".

19. **`src/chc/reputation.py:142,159` — medium (DoS) — The cache has no size limit or eviction.** Expired entries are never purged. Unique query strings make memory growth trivial.

20. **`src/chc/reputation.py:155-157` — medium — Lookups run one after another, each with a 10 s timeout.** With three feeds, one check can take 30 s or more, and there's no overall deadline.

21. **`src/chc/feeds/phishtank.py:14,18`, `misp.py:15,21`, `abuseipdb.py:16,21` — medium — The injected `client` is never used.** Every adapter calls the module-level `httpx.get` instead. The `httpx.Client()` each one creates is never used or closed, so it leaks, and connection pooling, transport settings and mocking through the client are all lost.

22. **`src/chc/feeds/phishtank.py:17-18` — medium — The PhishTank API key goes in the query string.** `httpx.HTTPStatusError` messages include the full request URL, so the key ends up in exceptions. Because of #2 those exceptions reach logs and error responses. The endpoint and parameter names are probably wrong too: PhishTank uses POST `checkurl.phishtank.com/checkurl/` with `app_key` and `format=json` **(verify)**.

23. **`src/chc/feeds/abuseipdb.py:33` — medium (verify) — `health()` calls `/blacklist`.** That endpoint has a strict daily quota, so routine health polling can use up the plan's limit.

24. **`src/chc/feeds/ingestor.py:20` — medium — The gate tests `commercial_ok` by truthiness.** `commercial_ok="false"` or `1` passes. It should be `feed.commercial_ok is not True`, so the gate fails closed.

25. **`src/chc/models.py:14-19` — medium — `CheckRequest` validation doesn't match `normalize_url`.** The prefix check is case-sensitive and doesn't allow leading whitespace, so `HTTPS://x` is rejected here but accepted by `normalize_url`. Bare `http://` and `http://127.0.0.1` are accepted. There's no `max_length`, although privacy model §1.4 asks for length validation.

26. **`src/chc/models.py:10` — medium — There's no request model for `check-domain`.** Architecture §4 says that endpoint accepts bare domains, but the only request model, `CheckRequest`, requires http(s).

## Low

27. **`src/chc/models.py:12` — low/medium — `user_id` comes from the client.** That lets callers attribute alerts to other users. It should come from the JWT. It also has no length or format limits.

28. **`src/chc/feeds/misp.py:20` — medium — The kind-to-type mapping is wrong.** `kind="ip"` maps to MISP type `"url"`. It should be `ip-dst`/`ip-src`.

29. **`src/chc/feeds/abuseipdb.py:24-29` — low/medium — AbuseIPDB scores aren't validated.** `None` or `"90"` raises `TypeError`, and a score above 100 gives a confidence above 1. All three adapters call `.get` on `resp.json()` without checking that it's a dict.

30. **`src/chc/feeds/ingestor.py:15-25` — low — Gating is checked only once, at `enable()`.** Changing `commercial_ok` afterwards has no effect. `register` silently overwrites duplicate ids without updating `_enabled`, and doesn't check the protocol. There's no `disable()`. `ReputationService` copies the feed list at init, so revoking a feed requires a restart.

31. **`src/chc/feeds/abuseipdb.py:14` — low — `commercial_ok=True` is hardcoded.** Having a key doesn't prove a paid plan. A plain `bool` also can't represent URLhaus's conditional "⚠️" status (architecture §6).

32. **`src/chc/feeds/misp.py:13` — low — The MISP base URL isn't validated.** `http://` is allowed, which sends the API key in plaintext. If orgs can configure the URL, it's also an SSRF vector.

33. **`src/chc/reputation.py:125` — low — `sources` lists every feed that answered, including ones that said clean.** That misattributes a malicious verdict, against the threat model's "provenance recorded". Feeds with `source=None` are dropped silently.

34. **`src/chc/reputation.py:124` — low — Category and tie-break come from a single feed.** Ties are decided by feed order. A malicious verdict at confidence 0.01 overrides clean at 0.99, which is by design but means one noisy feed can cause false positives.

35. **`src/chc/reputation.py:154,159-160` — low — The cache returns shared objects.** The first call returns the cached object itself, and `replace()` makes a shallow copy that shares `sources`. A caller mutating the result changes the cache.

36. **`src/chc/reputation.py:159` — low — Every result is cached for the full TTL.** That includes "unknown" with no feeds, so a newly listed IOC can be missed for an hour. Concurrent misses aren't coalesced, so several requests can hit the feeds for the same indicator at once.

37. **`src/chc/reputation.py:86-90` — low — Domain validation is too loose in some ways and too strict in others.** It accepts `a..b`, labels with leading or trailing hyphens, all-numeric labels and over-long labels. It rejects unicode IDNs, which `normalize_url` accepts. It rejects `:` and `@` anywhere, including in the path.

38. **`src/chc/models.py:26,43,47,69` — low — Several fields are loosely typed.** `confidence` has no 0..1 bound. `AlertResponse.verdict` isn't validated. `created_at` is a `str`, not a datetime. `ErrorResponse.error` doesn't enforce the code/message/details shape or the code values. `org_id` and `user_id` are required although the schema allows NULL. Severity is low because these are API contract issues.

## Test quality

39. **`tests/test_reputation.py:138-156` — medium — `test_check_never_fetches_target_url` can't fail.** It uses a stub feed, so httpx is never involved. It also doesn't patch `httpx.Client` methods.

40. **`tests/test_feeds.py` (all lookup tests) — medium — The feed tests depend on the client bug in #21.** They pass `client=httpx.Client()` but monkeypatch module-level `httpx.get`, so they would break if the injected client were actually used. They don't check request params, headers or timeouts.

41. **`tests/test_feeds.py:67` — medium — The MISP fixture uses a list for `response`.** The real `attributes/restSearch` returns a dict, so this fixture hides #4. There's also no test where `Attribute` is empty.

42. **`tests/test_feeds.py:32,43` — medium — The PhishTank fixture uses made-up keys.** There's no case for "in database but not verified" or "verified but not valid".

43. **The test suite overall — medium — Nothing tests failure paths.** No HTTP errors, timeouts, malformed JSON, unexpected types, or one feed failing while others succeed. There are no kind-routing tests either.

44. **`tests/test_normalize.py:55-67` — medium — The SSRF tests have big gaps.** Missing cases include decimal/hex/octal/short IPv4, mapped/NAT64/6to4/`::` IPv6, trailing dots, `localhost`, CGNAT, the 172.31 and 172.32 boundaries, multicast and broadcast, backslash, ports, IPv6 output formatting, and the domain cases (`2130706433`, `a..b`).

45. **`tests/test_reputation.py` — medium — `check()` is only tested with `kind="url"`.** There are no tests for `kind=None`, `"ip"` or `"domain"`.

46. **`tests/test_ingestor.py` — medium — The gating tests are incomplete.** No test that `ReputationService` queries only enabled feeds (#1), no non-bool `commercial_ok` (#24), no default tier, no tier case variants, no duplicate registration.

47. **`tests/test_normalize.py:84-86` — low — One test passes for the wrong reason.** `javascript:alert(1)` is rejected because it contains `:`, not because of the scheme check. `normalize_domain("ftp://x.com")` isn't tested.

48. **`tests/test_reputation.py` — low — The merge tests are thin.** Nothing covers confidence tie-breaks, which feed's category wins, an invalid verdict string, or `sources` attribution.

49. **Minor test hygiene — low.** `import time` is unused (`tests/test_reputation.py:2`). The "RED phase" docstrings are stale. Each test leaks an unclosed `httpx.Client`. The `commercial_ok` adapter tests only check hardcoded constants.

## What to fix first

- **Feed calls:** wrap each lookup in `try/except`, route feeds by kind, and give the whole check one deadline (#2, #3, #20).
- **Gating:** have `ReputationService` take its feeds from a `FeedIngestor`, or re-check `commercial_ok is True` and the tier at init (#1, #24).
- **MISP and PhishTank:** rewrite both lookups against the real APIs and fix the test fixtures to match (#4–#6, #41, #42).
- **SSRF guard:** in the IP check, unwrap IPv6-embedded IPv4, reject anything with `not ip.is_global`, and reject the other IPv4 spellings. Then fix the IPv6 brackets, normalize to a canonical form, and validate `kind=None` and `"ip"` (#7–#16).
