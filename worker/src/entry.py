"""Cloudflare Python Worker entrypoint for the keyhunt coordination server.

Routes the same endpoints the stdlib server does, over Cloudflare D1:

  POST /v1/register, /v1/targets, /v1/block/request, /v1/block/complete,
       /v1/match, /v1/stats   -- sealed-envelope protocol (see pyprotocol.py)
  GET  /healthz               -- liveness
  GET  /  and  /stats.html    -- plain HTML dashboard

Bindings / configuration (set in wrangler.jsonc and via `wrangler secret`):
  DB               (D1 binding, required)   the coordination database
  SERVER_KEY       (secret, required)       JSON identity: {"ed25519","x25519",
                                            "ed25519_secret","x25519_secret"}
                                            -- produced by keygen.py
  SPACE_PREFIX     (var, optional)          pin the high-order prefix nibbles
  LEASE_SECONDS    (var, optional)          lease length, default 3600
  REQUIRE_APPROVAL (var, optional)          "1"/"true" to hold new nodes pending
"""

import json

from workers import Response, WorkerEntrypoint

import coordinator as COORD

MAX_BODY = 8 * 1024 * 1024


def _to_py(x):
    """Convert a D1 JsProxy row/object to a plain Python value."""
    if x is None:
        return None
    to_py = getattr(x, "to_py", None)
    if to_py is not None:
        return to_py()
    return x


def _env_str(env, name, default=None):
    v = getattr(env, name, None)
    if v is None:
        return default
    s = str(v)
    return s if s != "undefined" else default


class D1Adapter:
    """Adapts Cloudflare D1's JS statement API to the small async interface the
    Coordinator uses (first / all / run / batch), returning plain Python."""

    def __init__(self, d1):
        self.d1 = d1

    def _stmt(self, sql, args):
        stmt = self.d1.prepare(sql)
        return stmt.bind(*args) if args else stmt

    async def first(self, sql, *args):
        return _to_py(await self._stmt(sql, args).first())

    async def all(self, sql, *args):
        res = await self._stmt(sql, args).all()
        return [_to_py(r) for r in (res.results or [])]

    async def run(self, sql, *args):
        res = await self._stmt(sql, args).run()
        meta = res.meta
        return {
            "results": [_to_py(r) for r in (res.results or [])],
            "changes": int(getattr(meta, "changes", 0) or 0),
            "last_row_id": getattr(meta, "last_row_id", None),
        }

    async def batch(self, ops):
        stmts = [self._stmt(sql, args) for sql, args in ops]
        await self.d1.batch(stmts)


def _build_coordinator(env):
    raw = _env_str(env, "SERVER_KEY")
    if not raw:
        raise RuntimeError("SERVER_KEY secret is not set")
    secret = json.loads(raw)
    cfg = {
        "space_prefix": _env_str(env, "SPACE_PREFIX", "") or "",
        "lease_seconds": float(_env_str(env, "LEASE_SECONDS", "3600")),
        "require_approval": _env_str(env, "REQUIRE_APPROVAL", "") in ("1", "true", "True", "yes"),
    }
    return COORD.Coordinator(D1Adapter(env.DB), secret, cfg)


def _path(url):
    # request.url is a full URL string; take the path without query.
    s = str(url)
    i = s.find("://")
    if i != -1:
        s = s[i + 3:]
        s = s[s.find("/"):] if "/" in s else "/"
    q = s.find("?")
    return s[:q] if q != -1 else s


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        method = request.method
        path = _path(request.url)

        if method == "GET":
            if path == "/healthz":
                return Response.json({"ok": True, "service": "keyhunt-coord"})
            if path in ("/", "/stats.html"):
                try:
                    coord = _build_coordinator(self.env)
                    html = await coord.render_dashboard()
                except Exception as e:
                    return Response("dashboard error: %r" % (e,), status=500)
                return Response(html, headers={"content-type": "text/html; charset=utf-8"})
            return Response.json({"error": "not found"}, status=404)

        if method != "POST":
            return Response.json({"error": "method not allowed"}, status=405)

        body = await request.text()
        if not body or len(body) > MAX_BODY:
            return Response.json({"error": "bad or oversized body"}, status=413)

        try:
            coord = _build_coordinator(self.env)
        except Exception as e:
            return Response.json({"error": "server misconfigured: %r" % (e,)}, status=500)

        try:
            code, obj = await coord.handle(path, body)
        except Exception as e:
            print("fetch error: %r" % (e,))
            return Response.json({"error": "internal error"}, status=500)
        return Response.json(obj, status=code)
