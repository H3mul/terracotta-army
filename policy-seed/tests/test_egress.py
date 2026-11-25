import importlib.util
import pathlib
import shutil
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("egress", HERE / "tools" / "egress.py")
egress = importlib.util.module_from_spec(spec)
spec.loader.exec_module(egress)


def copy_repo() -> pathlib.Path:
    d = pathlib.Path(tempfile.mkdtemp())
    shutil.copytree(HERE / "egress", d / "egress")
    shutil.copytree(HERE / "generated", d / "generated")
    return d


class Names(unittest.TestCase):
    def test_good_names(self):
        for n in ("pypi.org", "files.pythonhosted.org", "*.crates.io", "a-b.example.co.uk"):
            self.assertEqual(egress.valid_name(n), n)

    def test_bad_names(self):
        for n in ("", "localhost", "198.51.100.7", "1.1.1.1", "[::1]", "foo", "Pypi.org", " pypi.org", "-x.com",
                  "a..b.com", "x.*.com", "*.*.com", "*", "*.com.", "db." + "internal", "kube.svc", "x.cluster.local",
                  "printer.local", "a" * 64 + ".com", "evil.com/path", "evil.com:8080", "ev il.com"):
            with self.assertRaises(egress.PolicyError, msg=n):
                egress.valid_name(n)


class Seed(unittest.TestCase):
    def test_seed_is_valid_and_generated_file_is_current(self):
        egress.check(HERE)
        self.assertGreaterEqual(len(egress.load(HERE)), 10)

    def test_rendered_policy_only_names_hosts_on_443(self):
        import json
        pol = json.loads(egress.render(egress.load(HERE)))
        self.assertEqual(pol["kind"], "CiliumNetworkPolicy")
        for rule in pol["spec"]["egress"]:
            self.assertEqual(set(rule), {"toFQDNs", "toPorts"})
            self.assertEqual(rule["toPorts"], [{"ports": [{"port": "443", "protocol": "TCP"}]}])
            for f in rule["toFQDNs"]:
                self.assertIn(set(f), ({"matchName"}, {"matchPattern"}))


class Add(unittest.TestCase):
    def setUp(self):
        self.root = copy_repo()
        self.addCleanup(shutil.rmtree, self.root)

    def run_add(self, *args):
        return egress.main(["--root", str(self.root), "add", *args])

    def test_add_updates_both_files_and_stays_valid(self):
        self.assertEqual(self.run_add("Crates.IO ", "--reason", "Rust crates", "--by", "agent"), 0)
        egress.check(self.root)
        names = {h["name"] for h in egress.load(self.root)}
        self.assertIn("crates.io", names)

    def test_add_is_idempotent_and_refuses_bad_input_without_touching_files(self):
        before = (self.root / "egress" / "workspace.toml").read_text()
        self.assertEqual(self.run_add("pypi.org", "--reason", "again"), 0)
        for host in ("10." + "1.1.1", "x.local", "*.*.io"):
            self.assertEqual(self.run_add(host, "--reason", "no"), 1)
        self.assertEqual(self.run_add("ok.example.com", "--reason", ""), 1)
        self.assertEqual(self.run_add("ok.example.com", "--reason", "x\ny"), 1)
        self.assertEqual(self.run_add("ok.example.com", "--reason", "x", "--port", "22"), 1)
        self.assertEqual((self.root / "egress" / "workspace.toml").read_text(), before)

    def test_a_hand_edited_generated_file_fails_the_check(self):
        g = self.root / "generated" / "workspace-egress.yaml"
        g.write_text(g.read_text().replace("pypi.org", "evil.example.com"))
        with self.assertRaises(egress.PolicyError):
            egress.check(self.root)

    def test_quotes_and_odd_characters_in_a_reason_survive_the_round_trip(self):
        self.assertEqual(self.run_add("x.example.com", "--reason", 'say "hi" \\ and é'), 0)
        got = {h["name"]: h for h in egress.load(self.root)}["x.example.com"]
        self.assertEqual(got["reason"], 'say "hi" \\ and é')


class Diff(unittest.TestCase):
    def test_diff_flags_wildcards_http_and_open_publishing_domains(self):
        base, head = copy_repo(), copy_repo()
        self.addCleanup(shutil.rmtree, base)
        self.addCleanup(shutil.rmtree, head)
        egress.main(["--root", str(head), "add", "*.example.org", "--reason", "mirror"])
        egress.main(["--root", str(head), "add", "bucket.s3.amazonaws.com", "--reason", "data", "--port", "80", "--port", "443"])
        out = egress.diff(base, head)
        self.assertIn("**opens** `*.example.org`", out)
        self.assertIn("wildcard", out)
        self.assertIn("plain HTTP", out)
        self.assertIn("a way out for data", out)
        self.assertIn("No change", egress.diff(base, base))


if __name__ == "__main__":
    unittest.main()
