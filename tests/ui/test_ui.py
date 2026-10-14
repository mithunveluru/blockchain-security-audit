import re

import pytest
from playwright.sync_api import expect

from tests.ui.conftest import TOKEN, VIEWER, Server

ROUTES = ["overview", "alerts", "network", "ledger", "health", "copilot", "settings"]


def goto(page, route, wait=".page > *"):
    page.goto(f"{page.base}/#/{route}")
    page.wait_for_selector(wait, timeout=10000)
    page.wait_for_timeout(500)


def overflow(page):
    return page.evaluate("document.documentElement.scrollWidth - innerWidth")


def test_sign_in_rejects_bad_token_and_accepts_good_one(make_page):
    page = make_page(signed_in=False)
    page.goto(page.base)
    page.fill("#token", "x" * 20)
    page.click("button[type=submit]")
    expect(page.locator("[role=alert]")).to_contain_text("not accepted")
    page.fill("#token", TOKEN)
    page.click("button[type=submit]")
    expect(page.locator(".sidebar")).to_be_visible()
    assert not page.evaluate("sessionStorage.getItem('blockaudit.token')") == ""


@pytest.mark.parametrize("route", ROUTES)
def test_every_route_renders_without_console_problems(make_page, route):
    page = make_page()
    goto(page, route)
    expect(page.locator(".crumbs h1")).not_to_be_empty()
    expect(page.locator(".nav a[aria-current=page]")).to_have_attribute("data-route", route)
    assert page.problems == [], page.problems
    assert overflow(page) <= 1


@pytest.mark.parametrize("size", [(375, 800), (768, 1024), (1024, 768), (1440, 900), (1920, 1080)])
def test_no_horizontal_overflow_at_any_breakpoint(make_page, size):
    page = make_page(*size)
    for route in ROUTES:
        goto(page, route)
        assert overflow(page) <= 1, f"{route} overflows at {size}"
    assert page.problems == []


def test_mobile_uses_tab_bar_and_sub_bar_instead_of_sidebar(make_page):
    page = make_page(375, 800)
    goto(page, "overview")
    expect(page.locator(".sidebar")).to_be_hidden()
    expect(page.locator(".tabbar")).to_be_visible()
    expect(page.locator(".subbar")).to_be_visible()
    box = page.locator(".tabbar a").first.bounding_box()
    assert box["height"] >= 44 and box["width"] >= 44, "touch targets"
    page.click(".tabbar button")
    expect(page.locator("[role=menu]")).to_be_visible()


def test_investigation_workflow(make_page, sim_server):
    page = make_page()
    goto(page, "alerts", ".arow")
    rows = page.locator(".arow")
    assert rows.count() >= 2
    rows.first.click()
    expect(page.locator(".ex-detail")).to_be_visible()
    expect(page.locator(".ex-detail h1")).not_to_be_empty()
    # evidence
    page.click("#tab-evidence")
    expect(page.locator(".ex-detail table")).to_be_visible()
    # ledger record checks out
    page.click("#tab-ledger")
    expect(page.locator(".ex-detail .notice.ok")).to_contain_text("checks out", timeout=8000)
    # timeline shows this alert and context
    page.click("#tab-timeline")
    expect(page.locator(".timeline li.now")).to_be_visible(timeout=8000)
    # the list kept its place while the detail changed
    assert page.locator(".arow[aria-selected=true]").count() == 1
    # copilot answer cites real records that open
    page.click("#tab-copilot")
    page.get_by_role("button", name="Why was this alert triggered?").click()
    page.wait_for_selector(".co-a", timeout=10000)
    src = page.locator(".co-src a").first
    expect(src).to_be_visible()
    assert re.search(r"#/(alerts|ledger)/", src.get_attribute("href"))
    # esc closes the detail and keeps the list
    page.keyboard.press("Escape")
    expect(page.locator(".ex-detail")).to_be_hidden()
    assert page.locator(".arow").count() >= 2
    assert page.problems == [], page.problems


def test_alert_filters_narrow_the_list_and_survive_navigation(make_page):
    page = make_page()
    goto(page, "alerts", ".arow")
    total = page.locator(".arow").count()
    page.get_by_role("button", name=re.compile("Port scan")).click()
    page.wait_for_timeout(600)
    n = page.locator(".arow").count()
    assert 0 < n <= total and page.locator(".arow .ttl", has_text="Port scan").count() == n
    goto(page, "health")
    goto(page, "alerts", ".arow")
    assert page.locator(".arow").count() == n, "filter is remembered for the session"
    page.get_by_role("button", name="Clear all").click()
    page.wait_for_timeout(500)
    assert page.locator(".arow").count() == total


def test_command_palette_and_keyboard_navigation(make_page):
    page = make_page()
    goto(page, "overview")
    page.keyboard.press("Control+k")
    dlg = page.get_by_role("dialog", name="Command palette")
    expect(dlg).to_be_visible()
    expect(page.locator("#root input[role=combobox], .palette input")).to_be_focused()
    page.keyboard.type("ledger")
    page.keyboard.press("Enter")
    expect(page.locator(".crumbs h1")).to_have_text("Audit ledger")
    page.keyboard.press("Control+k")
    page.keyboard.press("Escape")
    expect(dlg).to_be_hidden()
    # go-to chords and list navigation
    page.keyboard.press("g")
    page.keyboard.press("a")
    expect(page.locator(".crumbs h1")).to_have_text("Alerts")
    page.wait_for_selector(".arow")
    page.locator(".ex-scroll ul").focus()
    page.keyboard.press("j")
    expect(page.locator(".ex-detail")).to_be_visible()


def test_skip_link_and_visible_focus(make_page):
    page = make_page()
    goto(page, "overview")
    page.keyboard.press("Tab")
    assert page.evaluate("document.activeElement.className") == "skip"
    page.wait_for_timeout(400)
    assert page.evaluate("getComputedStyle(document.activeElement).top") == "10px", "skip link slides into view"
    page.keyboard.press("Tab")
    ring = page.evaluate("(() => { const s = getComputedStyle(document.activeElement); return s.outlineStyle + ' ' + s.outlineWidth; })()")
    assert "solid" in ring


def test_tabs_support_arrow_keys(make_page):
    page = make_page()
    goto(page, "alerts", ".arow")
    page.locator(".arow").first.click()
    page.wait_for_selector("#tab-summary")
    page.locator("#tab-summary").focus()
    page.keyboard.press("ArrowRight")
    expect(page.locator("#tab-evidence")).to_have_attribute("aria-selected", "true")


def test_theme_toggle_persists(make_page):
    page = make_page(theme="dark")
    goto(page, "overview")
    page.click("button[aria-label='Switch theme']")
    assert page.evaluate("document.documentElement.dataset.theme") == "light"
    page.reload()
    page.wait_for_selector(".sidebar")
    assert page.evaluate("document.documentElement.dataset.theme") == "light"
    bg = page.evaluate("getComputedStyle(document.body).backgroundColor")
    assert bg != "rgb(8, 9, 12)"


def test_reduced_motion_is_honoured(make_page):
    page = make_page(reduced_motion="reduce")
    goto(page, "overview")
    assert page.evaluate("document.documentElement.dataset.motion") == "reduced"
    dur = page.evaluate("getComputedStyle(document.querySelector('.panel')).animationDuration")
    assert float(dur.rstrip("s")) < 0.01
    page2 = make_page(reduced_motion="no-preference")
    goto(page2, "overview")
    assert page2.evaluate("document.documentElement.dataset.motion") == "full"
    page2.click("button[aria-label='Account and preferences']")
    page2.get_by_role("menuitem", name="Reduce motion").click()
    assert page2.evaluate("document.documentElement.dataset.motion") == "reduced"


def test_server_text_can_never_become_markup(make_page):
    page = make_page()
    goto(page, "overview")
    out = page.evaluate("""async () => {
      const { h } = await import('/static/js/core/dom.js');
      const el = h('div', { style: 'color:red' }, '<img src=x onerror="window.__x=1"><script>window.__y=1</script>');
      document.body.append(el);
      await new Promise(r => setTimeout(r, 300));
      return { imgs: el.querySelectorAll('img,script').length, x: window.__x ?? null, y: window.__y ?? null, text: el.textContent.slice(0, 12) };
    }""")
    assert out == {"imgs": 0, "x": None, "y": None, "text": "<img src=x o"}
    assert page.problems == []


def test_charts_show_tooltip_on_hover_and_keyboard(make_page):
    page = make_page()
    goto(page, "overview")
    plot = page.locator(".ct-plot").first
    box = plot.bounding_box()
    page.mouse.move(box["x"] + box["width"] - 30, box["y"] + box["height"] / 2)
    expect(page.locator(".ct-tip").first).to_be_visible()
    page.mouse.move(5, 5)
    plot.focus()
    page.keyboard.press("ArrowLeft")
    expect(page.locator(".ct-tip").first).to_be_visible()
    assert "alerts" in (plot.get_attribute("aria-label") or "").lower()


def test_network_map_and_flow_filter(make_page):
    page = make_page()
    goto(page, "network", ".topo canvas")
    assert page.locator(".topo canvas").evaluate("c => c.width > 100 && c.height > 100")
    page.locator(".dist-row").first.click()
    expect(page.locator(".filterbar .chip")).to_have_count(1)
    page.locator(".filterbar .chip").click()
    expect(page.locator(".filterbar .chip")).to_have_count(0)


def test_ledger_record_detail_and_chain(make_page):
    page = make_page()
    goto(page, "ledger", ".blocks li")
    expect(page.locator(".integrity.ok")).to_be_visible()
    page.locator(".blocks li").nth(1).click()
    expect(page.locator(".panel h2", has_text=re.compile(r"Record #\d+"))).to_be_visible()
    page.get_by_role("tab", name="Merkle proof").click()
    expect(page.get_by_text("proof verifies")).to_be_visible()
    page.get_by_role("tab", name="Stored event").click()
    expect(page.locator("pre.code")).to_contain_text("event_type")


def test_disconnect_and_reconnect_is_visible_and_recovers(make_page, tmp_path):
    srv = Server(tmp_path, ENABLE_SIMULATION_MODE="1").start()
    try:
        page = make_page(server=srv)
        goto(page, "overview")
        expect(page.locator(".live")).to_have_class(re.compile(r"\bon\b"), timeout=10000)
        port = srv.port
        srv.stop()
        expect(page.locator(".live")).not_to_have_class(re.compile(r"\bon\b"), timeout=20000)
        srv2 = Server(tmp_path, ENABLE_SIMULATION_MODE="1")
        srv2.port, srv2.env["PORT"] = port, str(port)
        srv2.start()
        try:
            expect(page.locator(".live")).to_have_class(re.compile(r"\bon\b"), timeout=30000)
        finally:
            srv2.stop()
    finally:
        srv.stop()


def test_empty_and_degraded_states_are_honest(make_page, tmp_path):
    srv = Server(tmp_path, NETWORK_INTERFACE="no-such-iface0").start()
    try:
        page = make_page(server=srv)
        goto(page, "alerts")
        expect(page.get_by_role("heading", name="No alerts yet")).to_be_visible(timeout=8000)
        goto(page, "health")
        expect(page.locator(".health-row", has_text="Packet capture")).to_contain_text("unavailable", timeout=8000)
        expect(page.locator(".health-row", has_text="Packet capture")).to_contain_text("no-such-iface0")
        goto(page, "overview")
        expect(page.get_by_text("Nothing to investigate yet")).to_be_visible(timeout=8000)
        assert page.locator(".mode-tag").count() == 0, "live mode is not labelled as simulation"
    finally:
        srv.stop()


def test_invalid_stored_token_returns_to_sign_in(make_page, sim_server):
    page = make_page(signed_in=False)
    page.goto(sim_server.url)
    page.evaluate("sessionStorage.setItem('blockaudit.token','not-a-valid-token-0123456')")
    page.reload()
    expect(page.locator("#token")).to_be_visible()
    assert page.evaluate("sessionStorage.getItem('blockaudit.token')") in (None, "")


def test_viewer_sees_read_only_controls(make_page, sim_server):
    page = make_page(signed_in=False)
    page.goto(sim_server.url)
    page.fill("#token", VIEWER)
    page.click("button[type=submit]")
    page.wait_for_selector(".sidebar")
    goto(page, "alerts", ".arow")
    page.locator(".arow").first.click()
    expect(page.locator("select[aria-label='Investigation status']")).to_be_disabled()
    expect(page.get_by_text("Your role can read notes but not add them")).to_be_visible()
    goto(page, "settings")
    expect(page.get_by_text("Only administrators can change the whitelist")).to_be_visible()
    expect(page.get_by_role("button", name="Add", exact=True)).to_have_count(0)


def test_copilot_drawer_opens_with_alert_context_and_returns_focus(make_page):
    page = make_page()
    goto(page, "alerts", ".arow")
    page.locator(".arow").first.click()
    page.wait_for_selector("#tab-summary")
    trigger = page.locator("button[aria-label='Ask the copilot']")
    trigger.focus()
    trigger.click()
    drawer = page.get_by_role("dialog", name="Investigation copilot")
    expect(drawer).to_be_visible()
    expect(drawer.get_by_text(re.compile(r"Context: alr-"))).to_be_visible()
    page.keyboard.press("Escape")
    expect(drawer).to_be_hidden()
    assert page.evaluate("document.activeElement.getAttribute('aria-label')") == "Ask the copilot"


def test_tampered_ledger_is_explained_in_plain_language_everywhere(make_page, tmp_path):
    import json
    import os
    srv = Server(tmp_path, ENABLE_SIMULATION_MODE="1").start()
    try:
        srv.seed()
        chain = str(tmp_path / "chain.json")
        lines = open(chain).read().splitlines()
        victim = next(i for i, ln in enumerate(lines) if '"alert"' in json.loads(ln)["data"] and "HIGH" in json.loads(ln)["data"])
        b = json.loads(lines[victim])
        b["data"] = b["data"].replace("HIGH", "LOW")
        lines[victim] = json.dumps(b, sort_keys=True)
        open(chain + ".x", "w").write("\n".join(lines) + "\n")
        os.replace(chain + ".x", chain)
        page = make_page(server=srv)
        goto(page, "ledger")
        expect(page.locator(".integrity.bad")).to_be_visible(timeout=15000)
        expect(page.get_by_text("Contents no longer match the stored hash")).to_be_visible()
        expect(page.get_by_text("changed outside BlockAudit")).to_be_visible()
        expect(page.locator(".blocks li.bad")).to_have_count(1)
        page.locator(".blocks li.bad").click()
        expect(page.get_by_text("This record fails verification")).to_be_visible()
        goto(page, "overview")
        expect(page.get_by_text("Ledger integrity failure detected")).to_be_visible(timeout=8000)
        goto(page, "health")
        expect(page.locator(".health-row", has_text="Integrity monitor")).to_contain_text("degraded")
        assert page.problems == [], page.problems
    finally:
        srv.stop()


@pytest.mark.parametrize("theme,size", [("dark", (1440, 900)), ("light", (1440, 900)), ("dark", (375, 800)), ("light", (375, 800))])
def test_axe_wcag_audit_finds_no_violations(make_page, theme, size):
    axe_mod = pytest.importorskip("axe_playwright_python.sync_playwright")
    page = make_page(*size, theme=theme)
    options = {"runOnly": {"type": "tag", "values": ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"]}}
    problems = []
    for route in ROUTES:
        goto(page, route)
        page.wait_for_timeout(800)
        result = axe_mod.Axe().run(page, options=options)
        for v in result.response["violations"]:
            problems.append(f"{route}: {v['id']} {[n['target'] for n in v['nodes'][:2]]}")
    goto(page, "alerts", ".arow")
    page.locator(".arow").first.click()
    page.wait_for_selector("#tab-summary")
    page.wait_for_timeout(800)
    for v in axe_mod.Axe().run(page, options=options).response["violations"]:
        problems.append(f"alert detail: {v['id']} {[n['target'] for n in v['nodes'][:2]]}")
    assert problems == [], problems
