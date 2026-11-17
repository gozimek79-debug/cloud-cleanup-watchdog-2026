import datetime as dt
import unittest
from unittest import mock
import io
import urllib.error

import watchdog

TOKEN = "synthetic-only-test-token-xxxxxxxxxxxxxxxx"
CREATED = "2026-11-16T12:00:00Z"
SERVER_ID = 123456789
IP_ID = 987654321


def manifest():
    result = dict(project_id=123456, project_name="synthetic-project",
        vm_id=SERVER_ID, vm_name="synthetic-vm", created_at=CREATED,
        cleanup_at="2026-11-16T18:00:00Z", deadline="2026-11-17T12:00:00Z",
        primary_ipv4_id=IP_ID)
    result["binding_hmac"] = watchdog.sign(result, TOKEN)
    return result


class FakeCloud:
    token = TOKEN
    def __init__(self, server=True, ip=True, other=False, ipv6=False):
        self.server, self.ip, self.other, self.ipv6 = server, ip, other, ipv6
        self.deletions = []

    def call(self, method, path):
        if method == "DELETE":
            self.deletions.append(path)
            if path == f"/servers/{SERVER_ID}":
                self.server = False
            elif path == f"/primary_ips/{IP_ID}":
                self.ip = False
            else:
                raise AssertionError("Unexpected DELETE")
            return {}
        if path == f"/servers/{SERVER_ID}":
            if self.server:
                return {"server": {"id": SERVER_ID}}
            raise watchdog.HttpFailure(404)
        collection = path.split("?")[0].lstrip("/")
        records = []
        if collection == "servers" and self.server:
            records = [dict(id=SERVER_ID, name="synthetic-vm", created=CREATED,
                public_net={"ipv4": {"id": IP_ID},
                    "ipv6": {"id": 444} if self.ipv6 else None})]
        if collection == "primary_ips" and self.ip:
            records = [dict(id=IP_ID, assignee_id=SERVER_ID if self.server else None)]
        if collection == "volumes" and self.other:
            records = [dict(id=111)]
        return {collection: records, "meta": {"pagination": {
            "page": 1, "next_page": None, "last_page": None}}}


class Tests(unittest.TestCase):
    def test_empty_project_preflight(self):
        self.assertEqual(watchdog.preflight(FakeCloud(server=False, ip=False)), "PREFLIGHT_OK")

    def test_nonempty_project_refused(self):
        with self.assertRaisesRegex(watchdog.Failure, "not empty"):
            watchdog.preflight(FakeCloud())

    def test_before_six_hours_no_delete(self):
        cloud = FakeCloud()
        result = watchdog.execute(manifest(), cloud,
            now=watchdog.timestamp("2026-11-16T17:59:59Z"))
        self.assertEqual(result, "ARMED")
        self.assertEqual(cloud.deletions, [])

    def test_delete_exact_server_and_leftover_ip(self):
        cloud = FakeCloud()
        result = watchdog.execute(manifest(), cloud,
            now=watchdog.timestamp("2026-11-16T18:00:00Z"), sleep=lambda _: None)
        self.assertEqual(result, "CLEANED")
        self.assertEqual(cloud.deletions,
            [f"/servers/{SERVER_ID}", f"/primary_ips/{IP_ID}"])

    def test_absent_before_delete_cannot_claim_cleaned(self):
        cloud = FakeCloud(server=False, ip=False)
        result = watchdog.execute(manifest(), cloud,
            now=watchdog.timestamp("2026-11-16T18:00:00Z"), sleep=lambda _: None)
        self.assertEqual(result, "ABSENT_NO_BILLING")
        self.assertEqual(cloud.deletions, [])

    def test_absent_with_billable_ip_fails(self):
        cloud = FakeCloud(server=False, ip=True)
        with self.assertRaisesRegex(watchdog.Failure, "billable resources"):
            watchdog.execute(manifest(), cloud,
                now=watchdog.timestamp("2026-11-16T18:00:00Z"), sleep=lambda _: None)

    def test_ipv6_unbound_refused_before_delete(self):
        cloud = FakeCloud(ipv6=True)
        with self.assertRaisesRegex(watchdog.Failure, "Unexpected server IPv6"):
            watchdog.execute(manifest(), cloud,
                now=watchdog.timestamp("2026-11-16T18:00:00Z"), sleep=lambda _: None)
        self.assertEqual(cloud.deletions, [])

    def test_primary_ip_delete_404_cannot_claim_cleaned(self):
        class VanishedIP(FakeCloud):
            def call(self, method, path):
                if method == "DELETE" and path == f"/primary_ips/{IP_ID}":
                    self.ip = False
                    raise watchdog.HttpFailure(404)
                return super().call(method, path)
        with self.assertRaises(watchdog.HttpFailure):
            watchdog.execute(manifest(), VanishedIP(),
                now=watchdog.timestamp("2026-11-16T18:00:00Z"), sleep=lambda _: None)

    def test_late_cleanup_is_distinguished(self):
        cloud = FakeCloud()
        result = watchdog.execute(manifest(), cloud,
            now=watchdog.timestamp("2026-11-17T12:00:00Z"), sleep=lambda _: None)
        self.assertEqual(result, "LATE_CLEANED")
        self.assertEqual(cloud.deletions,
            [f"/servers/{SERVER_ID}", f"/primary_ips/{IP_ID}"])

    def test_delete_404_cannot_claim_cleaned(self):
        class VanishedOnDelete(FakeCloud):
            def call(self, method, path):
                if method == "DELETE" and path == f"/servers/{SERVER_ID}":
                    self.server = False
                    raise watchdog.HttpFailure(404)
                return super().call(method, path)
        cloud = VanishedOnDelete()
        with self.assertRaises(watchdog.HttpFailure):
            watchdog.execute(manifest(), cloud,
                now=watchdog.timestamp("2026-11-16T18:00:00Z"), sleep=lambda _: None)

    def test_other_billable_resource_fails_closed(self):
        cloud = FakeCloud(other=True)
        with self.assertRaisesRegex(watchdog.Failure, "Billable resource remains"):
            watchdog.execute(manifest(), cloud,
                now=watchdog.timestamp("2026-11-16T18:00:00Z"), sleep=lambda _: None)
        self.assertEqual(cloud.deletions, [f"/servers/{SERVER_ID}"])

    def test_wrong_token_refused_before_api(self):
        cloud = FakeCloud()
        cloud.token = "different-synthetic-token-xxxxxxxxxxxxx"
        with self.assertRaisesRegex(watchdog.Failure, "signature"):
            watchdog.execute(manifest(), cloud)
        self.assertEqual(cloud.deletions, [])

    def test_wrong_server_refused(self):
        class WrongCloud(FakeCloud):
            def call(self, method, path):
                result = super().call(method, path)
                if path.startswith("/servers?") and result["servers"]:
                    result["servers"][0]["name"] = "production"
                return result
        cloud = WrongCloud()
        with self.assertRaisesRegex(watchdog.Failure, "binding differs"):
            watchdog.execute(manifest(), cloud)
        self.assertEqual(cloud.deletions, [])

    def test_malformed_inventory_fails_closed(self):
        class Broken(FakeCloud):
            def call(self, method, path):
                return {"servers": []}
        with self.assertRaisesRegex(watchdog.Failure, "Incomplete API inventory"):
            watchdog.preflight(Broken())

    def test_pagination_uses_nullable_next_page(self):
        class TwoPages(FakeCloud):
            def call(self, method, path):
                if path.startswith("/servers?"):
                    page = 2 if "page=2" in path else 1
                    return {"servers": [{"id": page}], "meta": {"pagination": {
                        "page": page, "next_page": 2 if page == 1 else None,
                        "last_page": None}}}
                return super().call(method, path)
        self.assertEqual([entry["id"] for entry in watchdog.items(TwoPages(), "servers")], [1, 2])

    def test_pagination_missing_next_page_fails_closed(self):
        class Broken(FakeCloud):
            def call(self, method, path):
                return {"servers": [], "meta": {"pagination": {"page": 1}}}
        with self.assertRaisesRegex(watchdog.Failure, "Incomplete API inventory"):
            watchdog.items(Broken(), "servers")

    def test_images_query_is_filtered(self):
        class Filtered(FakeCloud):
            def call(self, method, path):
                self.path = path
                return super().call(method, path)
        cloud = Filtered(server=False, ip=False)
        watchdog.items(cloud, "images")
        self.assertIn("type=snapshot&type=backup", cloud.path)

    def test_cloud_http_404_fails_closed(self):
        error = urllib.error.HTTPError("https://api.hetzner.cloud/v1/servers/1", 404,
            "not found", {}, io.BytesIO(b""))
        with mock.patch.object(watchdog.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(watchdog.HttpFailure) as caught:
                watchdog.Cloud(TOKEN, sleep=lambda _: None).call("DELETE", "/servers/1")
        self.assertEqual(caught.exception.status, 404)

    def test_cloud_retry_then_success(self):
        transient = urllib.error.HTTPError("https://api.hetzner.cloud/v1/servers", 503,
            "unavailable", {}, io.BytesIO(b""))
        response = io.BytesIO(b'{"servers": []}')
        with mock.patch.object(watchdog.urllib.request, "urlopen",
                side_effect=[transient, response]) as opener:
            result = watchdog.Cloud(TOKEN, sleep=lambda _: None).call("GET", "/servers")
        self.assertEqual(result, {"servers": []})
        self.assertEqual(opener.call_count, 2)

    def test_main_rejects_nonprintable_token_before_network(self):
        with mock.patch.dict(watchdog.os.environ,
                {"HCLOUD_TOKEN": TOKEN + "\n", "TARGET_MANIFEST": ""}), \
                mock.patch.object(watchdog, "Cloud") as cloud, \
                mock.patch.object(watchdog.sys, "stderr", new_callable=io.StringIO):
            self.assertEqual(watchdog.main(), 2)
        cloud.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)

