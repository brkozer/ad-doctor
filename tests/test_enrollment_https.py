"""HTTPS and CES enrollment endpoints: the probe, the targets, AD-ADCS-019, redaction."""

from __future__ import annotations

import http.client
import json
import ssl
from typing import Any

import pytest

from ad_doctor import collect, probes, redact, report, viewer
from ad_doctor.checks import run_all
from ad_doctor.collect import Collector, Target, _ces_urls
from ad_doctor.model import Probes, Severity, Snapshot

from .test_checks import ids, only, snapshot

CA = "https://ca01.corp.example/certsrv/"
CES = "https://ces01.corp.example/Issuing-CA-7_CES_Kerberos/service.svc/CES"


class Response:
    def __init__(self, status: int, schemes: list[str]) -> None:
        self.status = status
        self.schemes = schemes

    def getheaders(self) -> list[tuple[str, str]]:
        return [("Server", "x"), *(("WWW-Authenticate", s) for s in self.schemes)]


def fake(status: int = 401, schemes: tuple[str, ...] = ("Negotiate", "NTLM")) -> Any:
    class Conn:
        calls: list[tuple[Any, ...]] = []  # noqa: RUF012
        made: dict[str, Any] = {}  # noqa: RUF012

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            type(self).made = {"args": args, **kwargs}

        def request(self, method: str, path: str, headers: dict[str, str]) -> None:
            self.calls.append((method, path, headers))

        def getresponse(self) -> Response:
            return Response(status, list(schemes))

        def close(self) -> None: ...

    return Conn


def broken(exc: Exception) -> Any:
    class Conn(fake()):  # type: ignore[misc]
        def request(self, *args: Any, **kwargs: Any) -> None:
            raise exc

    return Conn


# --- the probe ----------------------------------------------------------------------------


@pytest.mark.parametrize("schemes", [("NTLM",), ("Negotiate",), ("Negotiate", "NTLM")])
def test_windows_authentication_over_https_is_reported(
    monkeypatch: pytest.MonkeyPatch, schemes: tuple[str, ...]
) -> None:
    monkeypatch.setattr(probes.http.client, "HTTPSConnection", fake(schemes=schemes))
    assert probes.enrollment_https("10.0.0.1", "ca01.corp.example", 443) == (CA, None)


def test_probe_sends_nothing_but_the_host(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = fake()
    monkeypatch.setattr(probes.http.client, "HTTPSConnection", conn)
    probes.enrollment_https("h", "ca01.corp.example", 443, "/x/service.svc/CES")
    assert conn.calls == [("GET", "/x/service.svc/CES", {"Host": "ca01.corp.example"})]


def test_probe_accepts_any_server_certificate(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = fake()
    monkeypatch.setattr(probes.http.client, "HTTPSConnection", conn)
    probes.enrollment_https("h", "h", 443)
    assert conn.made["context"].verify_mode == ssl.CERT_NONE


@pytest.mark.parametrize(
    ("status", "schemes"),
    [(200, ()), (403, ("NTLM",)), (401, ("Basic",)), (401, ()), (404, ())],
)
def test_other_answers_are_not_windows_authentication(
    monkeypatch: pytest.MonkeyPatch, status: int, schemes: tuple[str, ...]
) -> None:
    monkeypatch.setattr(probes.http.client, "HTTPSConnection", fake(status, schemes))
    assert probes.enrollment_https("h", "h", 443) == (None, None)


def test_refused_means_no_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = broken(ConnectionRefusedError())
    monkeypatch.setattr(probes.http.client, "HTTPSConnection", conn)
    assert probes.enrollment_https("h", "h", 443) == (None, None)


@pytest.mark.parametrize(
    "exc",
    [
        TimeoutError("timed out"),
        ssl.SSLError("handshake failure"),
        http.client.BadStatusLine("garbage"),
        ValueError("bad header"),
    ],
)
def test_other_errors_are_not_a_clean_result(
    monkeypatch: pytest.MonkeyPatch, exc: Exception
) -> None:
    monkeypatch.setattr(probes.http.client, "HTTPSConnection", broken(exc))
    url, error = probes.enrollment_https("h", "h", 443)
    assert url is None and error


def test_http_path_is_probed_like_certsrv(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probes.http.client, "HTTPConnection", fake())
    assert probes.web_enrollment_ntlm("h", "ces", 80, "/a/CES") == ("http://ces/a/CES", None)


# --- what gets probed ---------------------------------------------------------------------


def test_ces_urls_from_the_stored_format() -> None:
    stored = f"1\n2\n0\n{CES}\n0"
    assert _ces_urls([stored, "1\n4\n0\nhttp://x/CES\n", "garbage"]) == [CES, "http://x/CES"]


def run(c: Collector, monkeypatch: pytest.MonkeyPatch, answers: dict[str, Any]) -> Probes:
    calls: list[tuple[Any, ...]] = []

    def web(connect: str, header: str, port: int, path: str) -> tuple[str | None, str | None]:
        calls.append(("http", connect, header, port, path))
        return answers.get("http", (None, None))

    def tls(connect: str, header: str, port: int, path: str) -> tuple[str | None, str | None]:
        calls.append(("https", connect, header, port, path))
        return answers.get("https", (None, None))

    monkeypatch.setattr(collect.probes, "web_enrollment_ntlm", web)
    monkeypatch.setattr(collect.probes, "enrollment_https", tls)
    result = Probes()
    c._probe_enrollment("dc01.corp.example", result)
    c.calls = calls  # type: ignore[attr-defined]
    return result


def collector(**kwargs: Any) -> Collector:
    target = Target("10.0.0.1", http_port=10080, https_port=10443, **kwargs)
    return Collector(None, target)  # type: ignore[arg-type]


def test_targets_are_certsrv_on_both_schemes_and_ces_urls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c = collector()
    c.ca_dns_hosts = ["DC01.corp.example"]
    c.ces_urls = [CES, "https://ces02.corp.example:8443/a/CES", "http://ces03.corp.example/b"]
    run(c, monkeypatch, {})
    assert c.calls == [  # type: ignore[attr-defined]
        ("http", "10.0.0.1", "DC01.corp.example", 10080, "/certsrv/"),
        ("https", "10.0.0.1", "DC01.corp.example", 10443, "/certsrv/"),
        ("https", "ces01.corp.example", "ces01.corp.example", 10443,
         "/Issuing-CA-7_CES_Kerberos/service.svc/CES"),
        ("https", "ces02.corp.example", "ces02.corp.example:8443", 8443, "/a/CES"),
        ("http", "ces03.corp.example", "ces03.corp.example", 10080, "/b"),
    ]  # fmt: skip


def test_ces_on_the_scanned_dc_uses_the_given_address(monkeypatch: pytest.MonkeyPatch) -> None:
    c = collector()
    c.ces_urls = ["https://dc01.corp.example/x/CES"]
    run(c, monkeypatch, {})
    assert c.calls[0][:2] == ("https", "10.0.0.1")  # type: ignore[attr-defined]


def test_port_zero_skips_that_scheme(monkeypatch: pytest.MonkeyPatch) -> None:
    c = Collector(None, Target("h", http_port=80, https_port=0))  # type: ignore[arg-type]
    c.ca_dns_hosts = ["ca01"]
    c.ces_urls = [CES]
    run(c, monkeypatch, {})
    assert [x[0] for x in c.calls] == ["http"]  # type: ignore[attr-defined]


def test_results_go_to_their_own_list_once(monkeypatch: pytest.MonkeyPatch) -> None:
    c = collector()
    c.ca_dns_hosts = ["ca01"]
    c.ces_urls = [CES]
    result = run(c, monkeypatch, {"https": (CA, None), "http": ("http://x/certsrv/", None)})
    assert result.web_enrollment_ntlm == ["http://x/certsrv/"]
    assert result.enrollment_https == [CA]


def test_probe_error_ends_up_in_a_note(monkeypatch: pytest.MonkeyPatch) -> None:
    c = collector()
    c.ca_dns_hosts = ["ca01"]
    result = run(c, monkeypatch, {"https": (None, "handshake failure")})
    assert result.enrollment_https == []
    assert c.notes == ["https://ca01/certsrv/ not probed: handshake failure"]


@pytest.mark.parametrize("url", ["https://", "https://host:notaport/x", "https://[bad/x"])
def test_a_broken_url_in_the_directory_gives_a_note(
    monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    c = collector()
    c.ces_urls = [url]
    run(c, monkeypatch, {})
    assert c.calls == []  # type: ignore[attr-defined]
    assert c.notes == [f"enrollment URL {url} not probed: not a valid URL"]


# --- AD-ADCS-019 --------------------------------------------------------------------------


def probed(**kwargs: Any) -> Snapshot:
    return snapshot(probes=Probes(**kwargs))


def test_https_endpoints_are_unknown_and_low() -> None:
    f = only(probed(enrollment_https=[CES, CA]), "AD-ADCS-019")
    assert f.severity is Severity.LOW
    assert f.objects == [CA, CES]
    assert "unknown" in f.detail


def test_https_alone_is_neither_esc8_nor_the_chain() -> None:
    found = ids(run_all(probed(enrollment_https=[CA], spooler_on_dc=True)))
    assert "AD-ADCS-019" in found
    assert not {"AD-ADCS-010", "AD-CHAIN-003"} & found


def test_quiet_without_https_endpoints() -> None:
    assert "AD-ADCS-019" not in ids(run_all(probed(web_enrollment_ntlm=["http://x/certsrv/"])))


# --- snapshots, redaction, viewer ---------------------------------------------------------


def stored() -> Snapshot:
    return probed(
        enrollment_https=[CES],
        web_enrollment_ntlm=["http://ces02.corp.example/Other-CA_CES_Kerberos/service.svc/CES"],
    )


def test_endpoints_survive_the_snapshot_file() -> None:
    back = Snapshot.from_json(json.loads(json.dumps(stored().to_json())))
    assert back.probes.enrollment_https == [CES]
    assert not any("AD-ADCS-019" in n for n in back.notes)


def test_older_snapshot_loads_and_says_https_was_not_judged() -> None:
    data = json.loads(json.dumps(stored().to_json()))
    del data["probes"]["enrollment_https"]
    back = Snapshot.from_json(data)
    assert back.probes.enrollment_https == []
    assert any("AD-ADCS-019" in n for n in back.notes)


def test_redaction_covers_hosts_and_the_ca_name_in_the_path() -> None:
    out = redact.redact(json.loads(json.dumps(stored().to_json())), b"k")
    text = json.dumps(out["probes"])
    for secret in ("ces01", "ces02", "corp", "Issuing-CA-7", "Other-CA"):
        assert secret not in text, secret
    (url,) = out["probes"]["enrollment_https"]
    assert url.startswith("https://x") and url.endswith("/service.svc/CES")
    assert only(Snapshot.from_json(out), "AD-ADCS-019").objects == [url]


def test_redaction_keeps_the_certsrv_path() -> None:
    data = json.loads(json.dumps(probed(enrollment_https=[CA]).to_json()))
    (url,) = redact.redact(data, b"k")["probes"]["enrollment_https"]
    assert url.endswith("/certsrv/") and "ca01" not in url


def test_viewer_shows_the_endpoints() -> None:
    snap = stored()
    vm = viewer.viewmodel(report.Report(snap, run_all(snap)), snap, viewer.Options())
    (item,) = [f for f in vm["findings"] if f["id"] == "AD-ADCS-019"]
    assert item["objects"] == [CES]
    assert "unknown" in item["detail"]
