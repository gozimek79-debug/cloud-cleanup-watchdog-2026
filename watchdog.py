"""Generic, project-scoped Hetzner cleanup watchdog. Standard library only.

No project identity, server identity, credential, or private audit data belongs in
this public source file. Hetzner tokens are project-scoped; the token must be
created in the intended empty project and bound to a seen server before arming.
"""
import datetime as dt
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request

API = "https://api.hetzner.cloud/v1"
COLLECTIONS = ("servers", "primary_ips", "floating_ips", "volumes", "load_balancers", "images")


class Failure(Exception):
    pass


class HttpFailure(Failure):
    def __init__(self, status):
        self.status = status
        super().__init__("HTTP request failed")


def timestamp(value):
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise Failure("Timestamp has no time zone")
    return parsed.astimezone(dt.timezone.utc)


def canonical(manifest):
    keys = ("project_id", "project_name", "vm_id", "vm_name", "created_at",
            "cleanup_at", "deadline", "primary_ipv4_id")
    return json.dumps({key: manifest[key] for key in keys}, sort_keys=True,
                      separators=(",", ":")).encode()


def sign(manifest, token):
    return hmac.new(token.encode("ascii"), canonical(manifest), hashlib.sha256).hexdigest()


class Cloud:
    def __init__(self, token, sleep=time.sleep):
        self.token = token
        self.sleep = sleep

    def call(self, method, path):
        if method not in ("GET", "DELETE") or not path.startswith("/") or ".." in path:
            raise Failure("Invalid request")
        request = urllib.request.Request(API + path, method=method,
            headers={"Authorization": "Bearer " + self.token, "Accept": "application/json"})
        for attempt in range(5):
            try:
                with urllib.request.urlopen(request, timeout=15) as response:
                    body = response.read(2_000_000)
                    return json.loads(body) if body else {}
            except urllib.error.HTTPError as error:
                if error.code == 404:
                    raise HttpFailure(404) from None
                if error.code not in (408, 429, 500, 502, 503, 504) or attempt == 4:
                    raise HttpFailure(error.code) from None
            except (urllib.error.URLError, TimeoutError):
                if attempt == 4:
                    raise HttpFailure(0) from None
            self.sleep(min(2 ** attempt, 8))
        raise AssertionError("Unreachable")


def items(cloud, collection):
    if collection not in COLLECTIONS:
        raise Failure("Unknown collection")
    output = []
    page = 1
    while page <= 100:
        response = cloud.call("GET", f"/{collection}?page={page}&per_page=50")
        batch = response.get(collection)
        pagination = response.get("meta", {}).get("pagination", {})
        if not isinstance(batch, list) or not isinstance(pagination.get("last_page"), int):
            raise Failure("Incomplete API inventory")
        output.extend(batch)
        if page >= pagination["last_page"]:
            return output
        page += 1
    raise Failure("Inventory too large")


def billable(cloud):
    result = {}
    for collection in COLLECTIONS:
        batch = items(cloud, collection)
        if collection == "images":
            batch = [entry for entry in batch if entry.get("type") in ("snapshot", "backup")]
        if batch:
            result[collection] = batch
    return result


def validate(manifest, token):
    if not isinstance(manifest.get("project_id"), int) or manifest["project_id"] <= 0:
        raise Failure("Project binding invalid")
    if not isinstance(manifest.get("vm_id"), int) or manifest["vm_id"] <= 0:
        raise Failure("Server binding invalid")
    if not isinstance(manifest.get("primary_ipv4_id"), int) or manifest["primary_ipv4_id"] <= 0:
        raise Failure("IPv4 binding invalid")
    if not manifest.get("project_name") or not manifest.get("vm_name"):
        raise Failure("Names missing")
    created, cleanup_at, deadline = map(timestamp,
        (manifest["created_at"], manifest["cleanup_at"], manifest["deadline"]))
    if not (created + dt.timedelta(hours=6) == cleanup_at and
            deadline == created + dt.timedelta(hours=24)):
        raise Failure("Deadline binding invalid")
    if not hmac.compare_digest(sign(manifest, token), manifest.get("binding_hmac", "")):
        raise Failure("Binding signature invalid")
    return created, cleanup_at, deadline


def preflight(cloud):
    if billable(cloud):
        raise Failure("Project is not empty")
    return "PREFLIGHT_OK"


def execute(manifest, cloud, now=None, sleep=time.sleep):
    created, cleanup_at, deadline = validate(manifest, cloud.token)
    now = now or dt.datetime.now(dt.timezone.utc)
    servers = items(cloud, "servers")
    if len(servers) > 1 or (servers and servers[0].get("id") != manifest["vm_id"]):
        raise Failure("Unexpected server inventory")
    if servers:
        server = servers[0]
        ipv4 = (server.get("public_net") or {}).get("ipv4") or {}
        if (server.get("name") != manifest["vm_name"] or
                timestamp(server["created"]) != created or
                ipv4.get("id") != manifest["primary_ipv4_id"]):
            raise Failure("Server binding differs from API")
    if now < cleanup_at:
        if not servers:
            raise Failure("Bound server disappeared before cleanup")
        return "ARMED"
    # An empty project at the start cannot prove that this watchdog deleted the VM.
    # The runner is ephemeral, so no earlier run's local state is trusted here.
    if not servers:
        raise Failure("Server absent before a verified delete request")
    # A 404 or lost DELETE response is ambiguous. Fail and alert instead of
    # reporting CLEANED without proof that this run's request was accepted.
    cloud.call("DELETE", f"/servers/{manifest['vm_id']}")
    for _ in range(30):
        try:
            cloud.call("GET", f"/servers/{manifest['vm_id']}")
        except HttpFailure as error:
            if error.status == 404:
                break
            raise
        sleep(10)
    else:
        raise Failure("Server remains after deletion")
    # Only the bound IPv4 may be deleted. Never delete an unknown asset.
    for _ in range(30):
        remaining = billable(cloud)
        ip_list = remaining.get("primary_ips", [])
        if not remaining:
            return "CLEANED"
        if set(remaining) == {"primary_ips"} and len(ip_list) == 1:
            ip = ip_list[0]
            if ip.get("id") == manifest["primary_ipv4_id"] and ip.get("assignee_id") is None:
                try:
                    cloud.call("DELETE", f"/primary_ips/{ip['id']}")
                except HttpFailure as error:
                    if error.status != 404:
                        raise
        sleep(10)
    raise Failure("Billable resource remains")


def main():
    try:
        token = os.environ.get("HCLOUD_TOKEN", "")
        if len(token) < 20 or not token.isascii():
            raise Failure("Project token missing")
        cloud = Cloud(token)
        raw = os.environ.get("TARGET_MANIFEST", "")
        if not raw:
            result = preflight(cloud)
        else:
            result = execute(json.loads(raw), cloud)
        print(result)  # Public CI output contains no IDs, IPs, or secrets.
        return 0
    except Exception as error:
        print("WATCHDOG_FAIL " + type(error).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

