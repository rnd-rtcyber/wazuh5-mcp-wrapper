"""
Wazuh 5 exploration client.

Wazuh 5 splits ruleset content differently from 4.x: rules and detectors live in
OpenSearch's Security Analytics plugin (wazuh-indexer-security-analytics), reachable
on the Indexer (port 9200), while agent management stays on the manager's classic
REST API (same shape as 4.x, port 55000). This client wraps both, confirmed live
against a real Wazuh 5.0.0-beta5 lab -- see WAZUH5-MCP-REPORT.md for the
verification record. Deliberately separate from WazuhClient/WazuhIndexerClient:
Wazuh 5's rules/decoders manager-side REST endpoints (the eventual /rules,
/decoders successors) do not exist yet on this build, so there is nothing there
for a shared client to wrap.

RULE WRITE PATH, CONFIRMED LIVE BY A SEPARATE INVESTIGATION (PCDSI FortiGate
rule migration, see Rule Translation/HANDOFF.md and the wazuh5-ruleset-migration
skill's methodology.md): rule creation does NOT go through the Indexer
(port 9200) at all. That port only exposes `_search` for rules/detectors --
confirmed live, a raw POST for create against it 404s/405s. The real write path
is a *third*, separate server: the dashboard's own Node process
(securityAnalyticsDashboards plugin), which happens to listen on 443 and reuse
the same `/_plugins/_security_analytics/...` path prefix as the Indexer route
purely by convention, not because it's the same backend. Every non-GET call to
this server needs an `osd-xsrf: true` header or you get a generic "no handler
found" error that looks like a wrong path. The request body shape is also NOT
the dashboard UI's own YAML-editor shape -- see create_rule()'s docstring for
the exact, source-read-confirmed shape `WazuhRuleService.buildRuleResource()`
actually expects.

DECODER WRITE PATH, CONFIRMED LIVE BY A LATER, SEPARATE EXPLORATION (same
Rule Translation/HANDOFF.md and methodology.md): unlike rules, decoder
create/update/delete DOES live on the Indexer (port 9200), under a
`_content_manager` plugin distinct from `_security_analytics` -- confirmed
by a real create -> update -> delete round trip against a throwaway decoder.
No `osd-xsrf` header needed here (unlike the rule/dashboard path). The
promotion lifecycle (draft -> test -> custom) is ALSO exposed here, and is
generic across content types, not decoder-specific: `GET .../promote?space=X`
returns a `changes` object describing everything pending promotion out of
space X; POSTing that same object back to `.../promote` (with `space` again)
executes it. See create_decoder()/promote_content()'s docstrings for the
exact confirmed shapes and the open questions (partial-changes promotion was
never tested; only "promote everything pending" was confirmed).
"""

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


class Wazuh5Client:
    """Client for a Wazuh 5.x manager (classic agent API), its Indexer's
    Security Analytics plugin (rule/detector search), and its dashboard's own
    Node server (the actual rule/detector write path)."""

    def __init__(
        self,
        manager_host: str,
        manager_port: int,
        manager_user: str,
        manager_pass: str,
        indexer_host: str,
        indexer_port: int,
        indexer_user: str,
        indexer_pass: str,
        dashboard_host: Optional[str] = None,
        dashboard_port: int = 443,
        dashboard_user: Optional[str] = None,
        dashboard_pass: Optional[str] = None,
        verify_ssl: bool = False,
    ):
        self.manager_base_url = f"{self._normalize(manager_host)}:{manager_port}"
        self.manager_user = manager_user
        self.manager_pass = manager_pass
        self.indexer_base_url = f"{self._normalize(indexer_host)}:{indexer_port}"
        self.indexer_user = indexer_user
        self.indexer_pass = indexer_pass
        # The dashboard is a genuinely separate server from the Indexer (see module
        # docstring); default its host/creds to the Indexer's own if not given
        # separately, since on a typical single-node lab they're the same box and
        # the same admin credentials, but keep them independently configurable
        # since that isn't guaranteed on a real deployment.
        _dash_host = dashboard_host or indexer_host
        self.dashboard_base_url = f"{self._normalize(_dash_host)}:{dashboard_port}"
        self.dashboard_user = dashboard_user or indexer_user
        self.dashboard_pass = dashboard_pass or indexer_pass
        self.verify_ssl = verify_ssl
        self._manager_token: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None
        self._auth_lock = asyncio.Lock()

    @staticmethod
    def _normalize(host: str) -> str:
        host = host.strip().rstrip("/")
        if not host.startswith("http://") and not host.startswith("https://"):
            host = f"https://{host}"
        return host

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(verify=self.verify_ssl, timeout=30)
        return self._client

    async def _authenticate_manager(self) -> None:
        client = await self._get_client()
        resp = await client.post(
            f"{self.manager_base_url}/security/user/authenticate",
            auth=(self.manager_user, self.manager_pass),
        )
        resp.raise_for_status()
        self._manager_token = resp.json()["data"]["token"]

    async def get_agents(self, limit: int = 100) -> Dict[str, Any]:
        """GET /agents on the Wazuh 5 manager's classic REST API.

        Confirmed live and unchanged from 4.x's response shape: affected_items,
        total_affected_items, etc. This is the one piece of the classic manager API
        confirmed still fully intact on this build.
        """
        client = await self._get_client()
        async with self._auth_lock:
            if not self._manager_token:
                await self._authenticate_manager()
        headers = {"Authorization": f"Bearer {self._manager_token}"}
        resp = await client.get(f"{self.manager_base_url}/agents", params={"limit": limit}, headers=headers)
        if resp.status_code == 401:
            async with self._auth_lock:
                await self._authenticate_manager()
            headers = {"Authorization": f"Bearer {self._manager_token}"}
            resp = await client.get(f"{self.manager_base_url}/agents", params={"limit": limit}, headers=headers)
        resp.raise_for_status()
        return resp.json()

    async def search_rules(
        self, query_string: Optional[str] = None, size: int = 20, pre_packaged: bool = True
    ) -> Dict[str, Any]:
        """POST /_plugins/_security_analytics/rules/_search on the Indexer.

        Confirmed live: this endpoint requires POST, not GET (a GET 405s); and a
        proper OpenSearch query DSL body, not a bare object -- an empty/malformed
        body 400s with "inner bool query clause cannot be null".
        """
        client = await self._get_client()
        body: Dict[str, Any] = {"size": size}
        body["query"] = {"query_string": {"query": query_string}} if query_string else {"match_all": {}}
        resp = await client.post(
            f"{self.indexer_base_url}/_plugins/_security_analytics/rules/_search",
            params={"pre_packaged": "true" if pre_packaged else "false"},
            json=body,
            auth=(self.indexer_user, self.indexer_pass),
        )
        resp.raise_for_status()
        return resp.json()

    async def search_detectors(self, size: int = 20) -> Dict[str, Any]:
        """POST /_plugins/_security_analytics/detectors/_search on the Indexer.

        Confirmed live: a bare POST to /detectors (no _search suffix) is a CREATE
        call and 400s with "Detector name is null" -- the _search suffix is
        required to list rather than accidentally attempt to create one.
        """
        client = await self._get_client()
        resp = await client.post(
            f"{self.indexer_base_url}/_plugins/_security_analytics/detectors/_search",
            json={"query": {"match_all": {}}, "size": size},
            auth=(self.indexer_user, self.indexer_pass),
        )
        resp.raise_for_status()
        return resp.json()

    async def search_integrations(self, query_string: Optional[str] = None, size: int = 50) -> Dict[str, Any]:
        """POST /_plugins/_security_analytics/integrations/_search on the DASHBOARD (not the Indexer).

        Confirmed live: this is the dashboard's own route (needs osd-xsrf, dashboard
        creds), found via the same investigation that confirmed create_rule()'s write
        path. Exists specifically to resolve the integration id a rule must be created
        against -- `logsource.product`/an integration's display name (e.g.
        'test_fortinet') is a separate value from its real id (a UUID), and every rule
        create call needs the real id. Match on the returned
        hits[].?._source.document.metadata.title (the display name) to find the id at
        hits[].?._source.document.id, not the OpenSearch `_id` (several duplicate
        `_id`s were observed for the same integration across its draft/test/custom
        space copies during the confirming investigation -- `document.id` is the
        stable one).
        """
        client = await self._get_client()
        body: Dict[str, Any] = {"query": {"query_string": {"query": query_string}} if query_string else {"match_all": {}}, "size": size}
        resp = await client.post(
            f"{self.dashboard_base_url}/_plugins/_security_analytics/integrations/_search",
            json=body,
            headers={"osd-xsrf": "true"},
            auth=(self.dashboard_user, self.dashboard_pass),
        )
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("message", resp.text)
            except Exception:
                detail = resp.text
            raise ValueError(f"Wazuh 5 integration search failed ({resp.status_code}): {detail}")
        return resp.json()

    @staticmethod
    def _build_rule_document(
        integration_category: str,
        level: str,
        detection: Dict[str, Any],
        title: str,
        author: str,
        description: str = "",
        status: str = "experimental",
        enabled: bool = True,
        references: Optional[List[str]] = None,
        false_positives: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        mitre: Optional[Dict[str, Any]] = None,
        compliance: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build the exact body `WazuhRuleService.buildRuleResource()` expects.

        Confirmed by reading that function's source directly on a real Wazuh 5 manager
        (`/usr/share/wazuh-dashboard/plugins/securityAnalyticsDashboards/server/`), not
        guessed -- and confirmed live by successfully creating a real rule this way.
        This is deliberately NOT the shape the dashboard's own YAML editor shows a
        human:
          - `category` is a flat top-level string, not nested under `logsource.product`.
          - `detection` must already be a JSON/YAML-encoded STRING -- the server runs
            `load(rule.detection)` (js-yaml) on it server-side. Passing a dict/object
            here silently produces nonsense on the server side, not a clean error.
          - `tags`/`false_positives` are arrays of `{"value": "..."}` objects, not
            plain strings.
          - CONFIRMED LIVE: a bare, non-dotted tag (e.g. a 4.x-style category tag with
            no dot in it) crashes the real OpenSearch Sigma compiler with an opaque
            Java "Index 1 out of bounds for length 1" error -- it almost certainly
            expects ATT&CK-style dotted tags (attack.t1110) and indexes into a
            "."-split result assuming at least two parts. Until a real safe dotted
            format is reconfirmed on your build, leave `tags` empty; this is why the
            parameter defaults to None -> [].
          - `mitre`/`compliance`, if given, are ALSO expected as JSON/YAML strings via
            a second `parseYamlField` call on the server -- this was read from source
            but never exercised live, unlike everything else in this shape. Treat a
            failure referencing either of these as the first thing to re-verify.
        """
        return {
            "category": integration_category,
            "level": level,
            "status": status,
            "enabled": enabled,
            "detection": json.dumps(detection),
            "tags": [{"value": t} for t in (tags or [])],
            "false_positives": [{"value": v} for v in (false_positives or [])],
            "metadata": {
                "title": title,
                "author": author,
                "description": description,
                "references": [r for r in (references or []) if r],
            },
            **({"mitre": json.dumps(mitre)} if mitre else {}),
            **({"compliance": json.dumps(compliance)} if compliance else {}),
        }

    async def create_rule(
        self,
        integration_id: str,
        integration_category: str,
        level: str,
        detection: Dict[str, Any],
        title: str,
        author: str,
        description: str = "",
        status: str = "experimental",
        enabled: bool = True,
        references: Optional[List[str]] = None,
        false_positives: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        mitre: Optional[Dict[str, Any]] = None,
        compliance: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """POST /_plugins/_security_analytics/rules on the DASHBOARD (port 443), NOT the
        Indexer (port 9200) -- confirmed live these are two different servers that
        happen to share a path prefix; the Indexer only supports `_search` for rules.

        `integration_id` must be the integration's real id (a UUID), from
        search_integrations() -- NOT its display name/`logsource.product` value.
        `integration_category` is that integration's own `category` field (e.g.
        'network-activity'), also from search_integrations() -- this becomes the
        rule's flat `category` field per _build_rule_document()'s docstring.
        `detection` is a plain Sigma detection dict (e.g.
        {"selection_1": {"event.action": "logged-in"}, "condition": "selection_1"});
        this method handles encoding it to the JSON string the server actually expects.

        Confirmed live: creates a real rule, visible in the dashboard's Rules list
        (Draft space) immediately after.
        """
        client = await self._get_client()
        document = self._build_rule_document(
            integration_category=integration_category,
            level=level,
            detection=detection,
            title=title,
            author=author,
            description=description,
            status=status,
            enabled=enabled,
            references=references,
            false_positives=false_positives,
            tags=tags,
            mitre=mitre,
            compliance=compliance,
        )
        resp = await client.post(
            f"{self.dashboard_base_url}/_plugins/_security_analytics/rules",
            json={"integrationId": integration_id, "document": document},
            headers={"osd-xsrf": "true"},
            auth=(self.dashboard_user, self.dashboard_pass),
        )
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("message", resp.text)
            except Exception:
                detail = resp.text
            raise ValueError(f"Wazuh 5 rule creation failed ({resp.status_code}): {detail}")
        return resp.json()

    async def update_rule(
        self,
        rule_id: str,
        integration_category: str,
        level: str,
        detection: Dict[str, Any],
        title: str,
        author: str,
        description: str = "",
        status: str = "experimental",
        enabled: bool = True,
        references: Optional[List[str]] = None,
        false_positives: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        mitre: Optional[Dict[str, Any]] = None,
        compliance: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """PUT /_plugins/_security_analytics/rules/{rule_id} on the DASHBOARD.

        CONFIRMED LIVE end to end, in two stages. First attempt included
        `integrationId` in the body (mirroring create_rule()) and failed with
        `[request body.integrationId]: definition for this key is missing` -- an
        OpenSearch schema-validation error meaning that field isn't part of this
        endpoint's accepted body shape at all, unlike create. A rule's integration
        association is apparently immutable once created and inferred server-side
        from `rule_id`, so this method takes no `integration_id` parameter. Second
        attempt, body reduced to bare `{"document": {...}}`, succeeded
        (`{"ok": true, "response": {"status": 200}}`) doing a real no-op update
        (identical content written back) against a live draft-space rule.
        """
        client = await self._get_client()
        document = self._build_rule_document(
            integration_category=integration_category,
            level=level,
            detection=detection,
            title=title,
            author=author,
            description=description,
            status=status,
            enabled=enabled,
            references=references,
            false_positives=false_positives,
            tags=tags,
            mitre=mitre,
            compliance=compliance,
        )
        resp = await client.put(
            f"{self.dashboard_base_url}/_plugins/_security_analytics/rules/{rule_id}",
            json={"document": document},
            headers={"osd-xsrf": "true"},
            auth=(self.dashboard_user, self.dashboard_pass),
        )
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("message", resp.text)
            except Exception:
                detail = resp.text
            raise ValueError(f"Wazuh 5 rule update failed ({resp.status_code}): {detail}")
        return resp.json()

    async def delete_rule(self, rule_id: str, forced: bool = False) -> Dict[str, Any]:
        """DELETE /_plugins/_security_analytics/rules/{rule_id} on the DASHBOARD.

        UNLIKE create_rule(), NOT independently confirmed live -- see update_rule()'s
        docstring, same caveat applies. `forced` maps to a `?forced=true` query param,
        following Security Analytics' documented convention elsewhere in the plugin for
        deleting a resource still referenced by something else (e.g. a Detector); this
        specific parameter's behavior against a real rule delete was not verified.
        """
        client = await self._get_client()
        resp = await client.delete(
            f"{self.dashboard_base_url}/_plugins/_security_analytics/rules/{rule_id}",
            params={"forced": "true"} if forced else None,
            headers={"osd-xsrf": "true"},
            auth=(self.dashboard_user, self.dashboard_pass),
        )
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("message", resp.text)
            except Exception:
                detail = resp.text
            raise ValueError(f"Wazuh 5 rule deletion failed ({resp.status_code}): {detail}")
        return resp.json()

    async def search_decoders(self, query_string: Optional[str] = None, size: int = 20) -> Dict[str, Any]:
        """POST /wazuh-threatintel-decoders-a/_search on the Indexer -- a PLAIN
        OpenSearch index search, NOT a `_content_manager` plugin route.

        Confirmed live: there is no working `_search` sub-route under
        `_plugins/_content_manager/decoders/` -- a POST to that path is parsed as
        an update/delete against a literal decoder id of "_search" (405, "allowed:
        [DELETE, PUT]"), not a search. Decoder content is readable directly from
        its backing index instead, the same index used throughout this project's
        earlier direct-OpenSearch cleanup work. Confirmed field names from a real
        document: `document.name` (e.g. "decoder/fortinet-utm-fix/0"), `document.id`
        (the real id create_decoder/update_decoder/delete_decoder use -- shared
        across a decoder's draft/test/custom copies, which are separate indexed
        documents distinguished by `space.name`), `document.normalize`/`document.check`/
        `document.parents` (the parsed Engine DSL), and `yaml` (the raw YAML source
        text, generated server-side from the JSON shape -- not something you supply).
        `document.name` is a keyword field (exact-match only via `term`, confirmed
        the same gotcha as `document.id` elsewhere in this project) -- this method
        uses `query_string` for free-text matching instead, which does not have that
        restriction; for an exact-name lookup, match on the returned `document.name`
        client-side instead of trying to query-string it precisely.
        """
        client = await self._get_client()
        body: Dict[str, Any] = {"query": {"query_string": {"query": query_string}} if query_string else {"match_all": {}}, "size": size}
        resp = await client.post(
            f"{self.indexer_base_url}/wazuh-threatintel-decoders-a/_search",
            json=body,
            auth=(self.indexer_user, self.indexer_pass),
        )
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("message", resp.text)
            except Exception:
                detail = resp.text
            raise ValueError(f"Wazuh 5 decoder search failed ({resp.status_code}): {detail}")
        return resp.json()

    async def create_decoder(self, integration_id: str, resource: Dict[str, Any]) -> Dict[str, Any]:
        """POST /_plugins/_content_manager/decoders on the INDEXER (port 9200) --
        NOT the dashboard port 443 rule-write path; a genuinely different plugin
        (`_content_manager`) than rules use (`_security_analytics`).

        Confirmed live end to end: created a real throwaway decoder, updated it,
        and deleted it. No `osd-xsrf` header needed here (unlike the rule write
        path). `resource` is a direct JSON object shaped like the Engine's own
        decoder DSL -- `name` (required, e.g. "decoder/my-decoder-fix/0"; the
        server rejects a missing/empty one with a schema error naming JSON path
        `/name`), plus whatever of `metadata`/`parents`/`definitions`/`check`/
        `normalize`/`enabled` your decoder needs -- this is the SAME shape as the
        YAML files this project already maintains, just as a parsed dict instead
        of YAML text (`yaml.safe_load()` a `.yml` file and pass the result
        directly). The server validates it against the real Engine schema and
        generates the YAML source representation itself; you never supply YAML
        text directly. Lands in the **draft** space only -- see promote_content()
        to move it forward from there, the same lifecycle rules go through.
        """
        client = await self._get_client()
        resp = await client.post(
            f"{self.indexer_base_url}/_plugins/_content_manager/decoders",
            json={"integration": integration_id, "resource": resource},
            auth=(self.indexer_user, self.indexer_pass),
        )
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("message", resp.text)
            except Exception:
                detail = resp.text
            raise ValueError(f"Wazuh 5 decoder creation failed ({resp.status_code}): {detail}")
        return resp.json()

    async def update_decoder(self, decoder_id: str, integration_id: str, resource: Dict[str, Any]) -> Dict[str, Any]:
        """PUT /_plugins/_content_manager/decoders/{decoder_id} on the INDEXER.

        Confirmed live (part of the same create/update/delete round trip as
        create_decoder()). UNLIKE update_rule() on the dashboard path, this one
        DOES want `integration` in the body -- confirmed by using the exact same
        `{"integration": ..., "resource": ...}` shape as create_decoder() and
        getting a clean 200, not a schema-rejection. Don't assume rule and decoder
        update bodies are symmetric just because both are `/{id}`-suffixed REST
        conventions; they are two different plugins with two different
        conventions, confirmed independently. Also lands in **draft** space only,
        same as create -- promote separately.
        """
        client = await self._get_client()
        resp = await client.put(
            f"{self.indexer_base_url}/_plugins/_content_manager/decoders/{decoder_id}",
            json={"integration": integration_id, "resource": resource},
            auth=(self.indexer_user, self.indexer_pass),
        )
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("message", resp.text)
            except Exception:
                detail = resp.text
            raise ValueError(f"Wazuh 5 decoder update failed ({resp.status_code}): {detail}")
        return resp.json()

    async def delete_decoder(self, decoder_id: str) -> Dict[str, Any]:
        """DELETE /_plugins/_content_manager/decoders/{decoder_id} on the INDEXER.

        Confirmed live (the last step of the create/update/delete round trip).
        Only removes the **draft** space copy -- confirmed by the same lifecycle
        as create/update; a decoder already promoted to test/custom is not
        retracted from those spaces by this call (not independently verified,
        but consistent with everything else observed about this space model).
        """
        client = await self._get_client()
        resp = await client.delete(
            f"{self.indexer_base_url}/_plugins/_content_manager/decoders/{decoder_id}",
            auth=(self.indexer_user, self.indexer_pass),
        )
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("message", resp.text)
            except Exception:
                detail = resp.text
            raise ValueError(f"Wazuh 5 decoder deletion failed ({resp.status_code}): {detail}")
        return resp.json()

    async def get_promotion_diff(self, space: str) -> Dict[str, Any]:
        """GET /_plugins/_content_manager/promote?space={space} on the INDEXER.

        Confirmed live. Returns a `changes` object listing every pending item of
        every content type (`decoders`, `rules`, `kvdbs`, `filters`,
        `integrations`, `policy`) waiting to be promoted OUT of `space` into the
        next stage (draft -> test, or test -> custom) -- e.g.
        `{"changes": {"decoders": [{"id": "...", "operation": "update"}], "rules": [], ...}}`.
        This is a genuinely generic, cross-content-type endpoint -- not
        decoder-specific despite being under `_content_manager`. Confirmed
        gotcha: this specific route reads `space` as a QUERY PARAMETER on GET,
        the opposite of promote_content()'s POST, which rejects `space` as a
        query param and wants it in the JSON body instead -- the two verbs on
        this same path parse their arguments completely differently, confirmed
        by two different error messages (`"unrecognized parameter: [space]"` for
        POST+query-param, a clean value for GET+query-param).
        """
        client = await self._get_client()
        resp = await client.get(
            f"{self.indexer_base_url}/_plugins/_content_manager/promote",
            params={"space": space},
            auth=(self.indexer_user, self.indexer_pass),
        )
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("message", resp.text)
            except Exception:
                detail = resp.text
            raise ValueError(f"Wazuh 5 promotion diff failed ({resp.status_code}): {detail}")
        return resp.json()

    async def promote_content(self, space: str, changes: Dict[str, Any]) -> Dict[str, Any]:
        """POST /_plugins/_content_manager/promote on the INDEXER -- executes a
        promotion previously previewed by get_promotion_diff().

        Confirmed live end to end: used to promote a real decoder fix from draft
        to test, then test to custom, with each hop verified by re-reading the
        decoder's content in the target space afterward. `changes` must be the
        exact object returned by `get_promotion_diff(space)["changes"]` -- passing
        an empty or malformed one fails loudly ("Changes object is required" /
        a raw Java NullPointerException naming an internal `sourceSpace` variable,
        confirmed live, both unhelpful for guessing the shape blind -- reading
        get_promotion_diff()'s own output was what actually revealed it).

        IMPORTANT, UNCONFIRMED RISK: this was only ever tested by passing back
        get_promotion_diff()'s FULL, unmodified `changes` object, which promotes
        EVERYTHING pending in that space -- every decoder, rule, kvdb, filter,
        integration, and policy change currently sitting in draft (or test), not
        just the one you care about. Whether submitting a trimmed-down `changes`
        object (e.g. only the one decoder id you want) promotes just that subset,
        or is rejected, or silently promotes everything anyway, was NOT tested.
        Treat "promote everything currently pending in this space" as this
        method's only confirmed behavior. Call get_promotion_diff() first and
        inspect it -- if it lists changes you don't recognize or don't want
        promoted yet, stop and ask before calling this.
        """
        client = await self._get_client()
        resp = await client.post(
            f"{self.indexer_base_url}/_plugins/_content_manager/promote",
            json={"space": space, "changes": changes},
            auth=(self.indexer_user, self.indexer_pass),
        )
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("message", resp.text)
            except Exception:
                detail = resp.text
            raise ValueError(f"Wazuh 5 content promotion failed ({resp.status_code}): {detail}")
        return resp.json()

    async def update_policy(self, policy_id: str, resource: Dict[str, Any]) -> Dict[str, Any]:
        """PUT /_plugins/_content_manager/policy/{policy_id} on the INDEXER (port 9200).

        Route existence confirmed live: a GET on this exact path returns
        `{"error": "Incorrect HTTP method ... allowed: [PUT]"}` (405), proving the
        route exists and only accepts PUT -- unlike decoders/rules, there is no
        matching GET/_search route under this plugin for policies (`GET
        /_plugins/_content_manager/policy(ies)` both 404 with "no handler found").
        The policy document's own shape (root_decoder/integrations/filters/
        enrichments/enabled/index_unclassified_events/index_discarded_events) was
        read directly from `wazuh-threatintel-policies-a` via a plain OpenSearch
        `_search` (not through this plugin) -- see this project's
        `Documentations/Translations/README.md` "policy" investigation for the
        full record. The actual PUT body shape (bare resource dict vs. a
        `{"resource": ...}` wrapper, whether `id`/`space` must be included or are
        rejected if present) is NOT independently confirmed -- a live probe was
        blocked by this session's own safety tooling before a real request body
        could be sent (this mutates a policy potentially shared across every
        custom-space integration, not just one). This method mirrors
        update_decoder()'s wrapper convention as the best-founded guess, but
        callers should treat the request shape as unconfirmed until a real call
        succeeds and this docstring is updated to say so.

        WRITE TOOL, BROAD AND SHARED IMPACT: a policy's `root_decoder` and
        `integrations` list govern decoding for every integration currently
        registered in that policy's space, not just the one you're working on
        (confirmed directly: this lab's single "Custom space" policy lists BOTH
        `test_fortinet` and a second, unrelated integration side by side, sharing
        one `root_decoder`). Changing it can silently break decoding for every
        OTHER integration sharing this policy. Read the full current policy
        document first (via a direct index read, not this method), confirm
        exactly what you intend to change, and get explicit human sign-off
        before calling this against a policy anyone else depends on.
        """
        client = await self._get_client()
        resp = await client.put(
            f"{self.indexer_base_url}/_plugins/_content_manager/policy/{policy_id}",
            json={"resource": resource},
            auth=(self.indexer_user, self.indexer_pass),
        )
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("message", resp.text)
            except Exception:
                detail = resp.text
            raise ValueError(f"Wazuh 5 policy update failed ({resp.status_code}): {detail}")
        return resp.json()

    async def test_logtest(
        self,
        event: str,
        integration: str,
        space: str = "standard",
        queue: int = 1,
        location: str = "master->api",
        trace_level: str = "NONE",
    ) -> Dict[str, Any]:
        """POST /_plugins/_content_manager/logtest on the Indexer.

        Confirmed live and real: found via the merged PR that introduced it
        (wazuh-indexer-security-analytics#96), then confirmed by direct call
        against this lab -- it returns a specific validation error
        ("Integration [x] not found in the 'y' space") rather than a 404,
        proving the route exists and processes input, even before a valid
        integration id/space combination is known. Unlike the 4.x manager's
        /logtest, this one lives on the Indexer, not the manager, and evaluates
        against a named integration's decoders/rules rather than a free-form
        session token.

        integration must be a real integration id already loaded in the target
        space; this client does not yet know how to list valid ones (no working
        listing endpoint found yet for this specific plugin route family).
        """
        client = await self._get_client()
        body = {
            "integration": integration,
            "space": space,
            "queue": queue,
            "location": location,
            "metadata": {},
            "event": event,
            "trace_level": trace_level,
        }
        resp = await client.post(
            f"{self.indexer_base_url}/_plugins/_content_manager/logtest",
            json=body,
            auth=(self.indexer_user, self.indexer_pass),
        )
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("message", resp.text)
            except Exception:
                detail = resp.text
            raise ValueError(f"Wazuh 5 logtest failed ({resp.status_code}): {detail}")
        return resp.json()
