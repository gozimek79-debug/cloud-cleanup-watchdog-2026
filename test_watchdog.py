import datetime as dt
import unittest

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
    def __init__(self, server=True, ip=True, other=False):
        self.server, self.ip, self.other = server, ip, other
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
                public_net={"ipv4": {"id": IP_ID}})]
        if collection == "primary_ips" and self.ip:
            records = [dict(id=IP_ID, assignee_id=SERVER_ID if self.server else None)]
        if collection == "volumes" and self.other:
            records = [dict(id=111)]
        return {collection: records, "meta": {"pagination": {"last_page": 1}}}


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


if __name__ == "__main__":
    unittest.main(verbosity=2)

