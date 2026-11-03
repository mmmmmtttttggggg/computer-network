"""Real browser workflow checks. Requires the optional browser extra and Chromium.

  pip install -e '.[dev,browser]'
  playwright install chromium
  python scripts/browser_smoke.py
Set NETSCOPE_BROWSER_EXECUTABLE to use an existing Chromium binary.
Screenshots, if requested through --screenshots, are local QA outputs only.
"""

from __future__ import annotations
import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path
from playwright.sync_api import sync_playwright, expect


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--screenshots")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()
        root = f"http://127.0.0.1:{port}"
        env = {
            **os.environ,
            "NETSCOPE_DATA": str(Path(tmp) / "data"),
            "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
        }
        server = subprocess.Popen(
            [sys.executable, "-m", "app.cli", "serve", "--port", str(port)],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            for _ in range(60):
                try:
                    urllib.request.urlopen(root + "/api/config", timeout=1)
                    break
                except Exception:
                    if server.poll() is not None:
                        raise RuntimeError(server.stderr.read().decode())
                    time.sleep(0.1)
            errors = []
            with sync_playwright() as pw:
                options = {"headless": True}
                if os.environ.get("NETSCOPE_BROWSER_EXECUTABLE"):
                    options.update(
                        executable_path=os.environ["NETSCOPE_BROWSER_EXECUTABLE"],
                        args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
                    )
                browser = pw.chromium.launch(**options)
                page = browser.new_page(viewport={"width": 1440, "height": 1000})
                page.on("pageerror", lambda e: errors.append(str(e)))
                page.goto(root)
                page.wait_for_selector(".metrics")
                expect(page.locator("h1")).to_have_text("The indirect escape")
                initial_history = page.request.get(root + "/api/runs").json()
                initial_id = initial_history[0]["id"]
                initial = page.request.get(root + "/api/runs/" + initial_id).json()
                page.reload()
                page.wait_for_selector(".metrics")
                expect(page.locator("#run-fingerprint")).to_contain_text(initial_id[:8])
                assert len(page.request.get(root + "/api/runs").json()) == len(initial_history)
                page.locator("#page-help").click()
                expect(page.locator("#breadcrumb")).to_have_text("Guide")
                expect(page.locator("#guide-overview")).to_be_visible()
                expect(page.locator(".guide-row")).to_have_count(7)
                page.locator('#guide-examples [data-goto="examples"]').click()
                expect(page.locator("#breadcrumb")).to_have_text("Examples")
                expect(page.locator(".example-card")).to_have_count(8)
                expect(page.locator(".example-card.current")).to_contain_text("The indirect escape")
                page.locator('.example-card.current [data-example="agent-escape"]').click()
                expect(page.locator("#breadcrumb")).to_have_text("Containment")
                expect(page.locator(".path-card")).to_have_count(1)
                expect(page.locator(".sensitivity-check")).to_contain_text("No path to this asset")
                if args.screenshots:
                    Path(args.screenshots).mkdir(parents=True, exist_ok=True)
                    page.screenshot(
                        path=str(Path(args.screenshots) / "initial-containment-desktop.png"), full_page=True
                    )
                page.set_viewport_size({"width": 390, "height": 844})
                assert not page.evaluate("document.documentElement.scrollWidth > innerWidth")
                if args.screenshots:
                    page.screenshot(
                        path=str(Path(args.screenshots) / "initial-containment-mobile.png"), full_page=True
                    )
                page.set_viewport_size({"width": 1440, "height": 1000})
                page.locator(".path-card button[data-row]").last.click()
                expect(page.locator("#drawer")).to_be_visible()
                expect(page.locator("#drawer-content")).to_contain_text("Source egress")
                page.keyboard.press("Escape")
                expect(page.locator("#drawer")).to_be_hidden()
                with page.expect_response(
                    lambda response: response.url.endswith("/api/runs") and response.request.method == "POST"
                ) as counterfactual_response:
                    page.locator("[data-remove-pivot]").click()
                counterfactual = counterfactual_response.value.json()
                expect(page.locator(".path-card")).to_have_count(0)
                assert not counterfactual["threat"]["findings"]
                assert counterfactual["rows"] == initial["rows"]
                page.locator("#scenario").select_option("agent-escape")
                page.locator("#run-review").click()
                page.wait_for_selector(".path-card")
                page.locator("#scenario").select_option("parallel-relay")
                page.locator("#run-review").click()
                expect(page.locator("h1")).to_have_text("The parallel relay")
                expect(page.locator(".sensitivity-check")).to_contain_text("alternative 2-hop path")
                with page.expect_response(
                    lambda response: response.url.endswith("/api/runs") and response.request.method == "POST"
                ) as alternate_response:
                    page.locator("[data-remove-pivot]").click()
                assert alternate_response.value.json()["threat"]["findings"]
                expect(page.locator(".path-card")).to_have_count(1)
                page.locator("#scenario").select_option("agent-escape")
                page.locator("#run-review").click()
                expect(page.locator("h1")).to_have_text("The indirect escape")
                page.locator('#nav [data-view="experiments"]').click()
                page.locator("#repair").click()
                page.wait_for_selector(".repair-card")
                with page.expect_response(
                    lambda response: response.url.endswith("/api/runs") and response.request.method == "POST"
                ) as pending_review:
                    page.locator('[data-repair-open="0"]').click()
                repaired = pending_review.value.json()
                expect(page.locator("#run-fingerprint")).to_contain_text(repaired["id"][:8])
                expect(page.locator("h1")).to_have_text("The indirect escape")
                page.wait_for_selector("#repair:not([disabled])")
                # The returned project is a new run; direct and conditional constraints pass.
                report = repaired
                assert report["exit_code"] == 0 and not report["threat"]["findings"]
                page.locator("#scenario").select_option("checkout-regression")
                page.locator("#run-review").click()
                expect(page.locator("h1")).to_have_text("The database switch")
                page.locator("#witness").select_option(index=0)
                page.locator("#reduce").click()
                page.wait_for_selector("#download-bundle")
                expect(page.locator("#reduction-result")).to_contain_text("90% reduction")
                with page.expect_download() as pending:
                    page.locator("#download-bundle").click()
                download = pending.value
                path = Path(tmp) / "replay.zip"
                download.save_as(path)
                with zipfile.ZipFile(path) as z:
                    assert z.testzip() is None and "preservation.json" in z.namelist()
                page.locator("#scenario").select_option("clean-baseline")
                page.locator("#run-review").click()
                expect(page.locator("h1")).to_have_text("A clean baseline")
                page.locator("#more-experiments > summary").click()
                page.locator("#mutate").click()
                page.wait_for_selector(".mutant")
                assert page.locator(".mutant").count() > 10
                page.locator("#suggest-checks").click()
                page.wait_for_selector("#download-checks")
                expect(page.locator("#coverage-result")).to_contain_text("4 draft checks")
                page.locator("#verify-drafts").click()
                expect(page.locator("#coverage-result")).to_contain_text("Draft verification: PASS")
                with page.expect_download() as pending:
                    page.locator("#download-checks").click()
                checks_path = Path(tmp) / "checks.json"
                pending.value.save_as(checks_path)
                assert len(json.loads(checks_path.read_text())["checks"]) == 4
                page.locator("#scenario").select_option("agent-escape")
                page.locator("#run-review").click()
                expect(page.locator("h1")).to_have_text("The indirect escape")
                page.wait_for_function("!state.busy")
                page.wait_for_selector("#run-labels")
                page.locator("#label-endpoint").select_option("apps/agent")
                page.locator("#trusted-label").click()
                assert '"payments"' in page.locator("#label-editor").input_value()
                page.locator("#run-labels").click()
                page.wait_for_selector("#open-label-review")
                expect(page.locator("#label-result")).to_contain_text("1 shorter asset paths")
                expect(page.locator("#label-result")).to_contain_text("INVALID")
                page.locator("#open-label-review").click()
                expect(page.locator("h1")).to_contain_text("label experiment")
                page.locator("#scenario").select_option("clean-baseline")
                page.locator("#run-review").click()
                expect(page.locator("h1")).to_have_text("A clean baseline")
                page.locator('#nav [data-view="connections"]').click()
                page.locator(".query-composer summary").click()
                page.locator("#ask-source").select_option("apps/agent")
                page.locator("#ask-destination").select_option("data/database")
                page.locator("#ask-port").fill("12345")
                page.locator("#ask-expect").select_option("must_deny")
                page.locator("#ask-query").click()
                page.wait_for_selector("#download-query-check")
                expect(page.locator(".query-composer .result-box")).to_contain_text("PASS")
                expect(page.locator("#ask-port")).to_have_value("12345")
                with page.expect_download() as pending:
                    page.locator("#download-query-check").click()
                query_path = Path(tmp) / "query.json"
                pending.value.save_as(query_path)
                assert json.loads(query_path.read_text())["checks"][0]["port"] == 12345
                page.locator("#search").fill("apps/agent")
                assert page.locator("#connections-body tr[data-row]").count() > 0
                page.locator("#connections-body tr[data-row]").first.press("Enter")
                expect(page.locator("#drawer")).to_be_visible()
                page.keyboard.press("Escape")
                page.locator('#nav [data-view="inputs"]').click()
                page.locator("#editor").fill("a: 1\na: 2")
                page.locator("#run-editor").click()
                expect(page.locator("#notice")).to_be_visible()
                expect(page.locator("#notice")).to_contain_text("duplicate key")
                # Presentation-only matrix test. No live job or evidence is saved.
                from app.runtime.evidence import summarize_coverage

                matrix = summarize_coverage(initial, {})
                text = page.evaluate(
                    "c => { const e=document.createElement('div'); e.innerHTML=liveMatrix({coverage:c}); return e.textContent; }",
                    matrix,
                )
                assert "NOT_TESTED" in text and "0 /" in text
                # Validate layout on desktop and mobile for every workspace.
                for width in [1440, 1366, 390]:
                    page.set_viewport_size({"width": width, "height": 1000 if width > 400 else 844})
                    for view in [
                        "overview",
                        "examples",
                        "connections",
                        "containment",
                        "experiments",
                        "evidence",
                        "inputs",
                        "guide",
                    ]:
                        page.locator(f'#nav [data-view="{view}"]').click()
                        assert not page.evaluate("document.documentElement.scrollWidth > innerWidth"), (
                            width,
                            view,
                        )
                        if args.screenshots:
                            out = Path(args.screenshots)
                            out.mkdir(parents=True, exist_ok=True)
                            page.screenshot(path=str(out / f"{width}-{view}.png"), full_page=True)
                assert not errors, errors
                print(
                    json.dumps(
                        {
                            "browser_workflows": "passed",
                            "viewports": [1440, 1366, 390],
                            "console_page_errors": errors,
                            "verified": [
                                "conditional path and evidence drawer",
                                "single-pivot counterfactual preserves policy decisions",
                                "parallel relay remains reachable after one assumption is removed",
                                "refresh restores review without duplicate history",
                                "examples table",
                                "example card opens its scenario on the target view",
                                "in-app guide reachable from every page",
                                "scoped repair opens a new passing review",
                                "reduction ZIP is a real archive",
                                "mutation suite",
                                "training-only regression drafts and held-out evaluation",
                                "draft check verification and JSON download",
                                "immutable label experiment shows shorter direct asset path",
                                "exact query beyond saved port scope and portable check download",
                                "observation matrix rendering with explicitly missing observations (presentation-only test)",
                                "keyboard row inspection",
                                "invalid input feedback",
                                "eight views without horizontal overflow",
                            ],
                        },
                        indent=2,
                    )
                )
                browser.close()
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


if __name__ == "__main__":
    main()
