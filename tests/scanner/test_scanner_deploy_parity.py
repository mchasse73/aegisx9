"""The two install paths (cloud-init via Terraform, the Ansible role) must install the
same toolchain the same way (#96)."""

from __future__ import annotations

import re

import yaml

from conftest import ROOT

INFRA = ROOT / "infra" / "scanner"
ROLE = ROOT / "automation/collections/ansible_collections/x9/aegisx9/roles/scanner"


def _tf_default(name: str) -> str:
    text = (INFRA / "variables.tf").read_text()
    block = re.search(rf'variable "{name}" \{{(.*?)\n\}}', text, re.S)
    assert block, name
    m = re.search(r'default\s*=\s*"([^"]*)"', block.group(1))
    assert m, f"{name} has no string default"
    return m.group(1)


def test_role_defaults_match_terraform() -> None:
    defaults = yaml.safe_load((ROLE / "defaults/main.yml").read_text())
    assert str(defaults["scanner_garak_version"]) == _tf_default("garak_version")
    assert str(defaults["scanner_torch_version"]) == _tf_default("torch_version")
    assert defaults["scanner_torch_index_url"] == _tf_default("torch_index_url")
    # The package ref is required on both paths: no default anywhere.
    assert defaults["scanner_package_ref"] == ""
    tf = (INFRA / "variables.tf").read_text()
    ref = re.search(r'variable "scanner_package_ref" \{(.*?)\n\}', tf, re.S)
    assert ref and "default" not in ref.group(1)


def test_template_installs_the_way_the_role_does() -> None:
    tpl = (INFRA / "cloud-init.sh.tftpl").read_text()
    tasks = (ROLE / "tasks/main.yml").read_text()
    for text in (tpl, tasks):
        assert "aegisx9@$${PKG_REF}#egg" not in text and "}}#egg" not in text
        assert "aegisx9[scanner] @ git+https://github.com/mchasse73/aegisx9@" in text
        assert "+cpu" in text and "--no-cache-dir" in text
    assert "garak==0.17.1" not in tpl and "download.pytorch.org" not in tpl
    # The signature check rejects expired, revoked and bad signatures, not only a
    # missing VALIDSIG (gpg prints VALIDSIG for an expired key too).
    for status in ("EXPKEYSIG", "REVKEYSIG", "EXPSIG", "BADSIG"):
        assert status in tpl
    # A failing secrets fetcher must not stop the timers from being enabled.
    timers = tpl.index("systemctl enable --now aegisx9-scan-daily.timer")
    assert "systemctl enable --now aegisx9-scanner-env" not in tpl
    assert timers < tpl.index("systemctl start aegisx9-scanner-env.service")
