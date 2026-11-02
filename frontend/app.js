(() => {
  const API = (window.API_BASE || "").replace(/\/$/, "");
  const $ = (s) => document.querySelector(s);

  const STATUS_LABEL = { pass: "Good", warn: "Improve", fail: "Fix", info: "Note" };
  const GRADE_TEXT = {
    A: "Strong setup. Keep it maintained.",
    B: "Mostly solid, with a few gaps worth closing.",
    C: "Several gaps an attacker could use.",
    D: "Important protections are missing.",
    F: "Basic protections are missing.",
  };

  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  // Render "Add: Header: value" fixes with the header in <code>.
  const fixHtml = (fix) => {
    const m = fix.match(/^(.*?:)\s(.+)$/);
    return m && /Add|record|TXT/i.test(m[1]) ? `${esc(m[1])} <code>${esc(m[2])}</code>` : esc(fix);
  };

  async function post(path, body) {
    const res = await fetch(`${API}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    let data = null;
    try { data = await res.json(); } catch { /* non-JSON */ }
    if (!res.ok) {
      const d = data?.detail;
      const msg = typeof d === "string" ? d : Array.isArray(d) ? d[0]?.msg : null;
      throw new Error(msg || `Request failed (${res.status}).`);
    }
    return data;
  }

  function renderReport(r) {
    $("#report-host").textContent = r.host;
    const when = new Date(r.scanned_at).toLocaleString("en-IN", { dateStyle: "medium", timeStyle: "short" });
    const s = r.summary;
    $("#report-meta").textContent = `${GRADE_TEXT[r.grade]} ${s.fail} to fix, ${s.warn} to improve, ${s.pass} good. Checked ${when}.`;

    const stamp = $("#stamp");
    stamp.dataset.grade = r.grade;
    stamp.setAttribute("aria-label", `Grade ${r.grade}, score ${r.score} out of 100`);
    $("#stamp-grade").textContent = r.grade;
    $("#stamp-score").textContent = `${r.score}/100`;
    // restart the stamp animation on re-scan
    stamp.style.animation = "none"; void stamp.offsetWidth; stamp.style.animation = "";

    const order = { fail: 0, warn: 1, pass: 2, info: 3 };
    const groups = {};
    for (const c of r.checks) (groups[c.category] ??= []).push(c);
    const worst = (list) => Math.min(...list.map((c) => order[c.status]));
    const html = Object.entries(groups)
      .sort((a, b) => worst(a[1]) - worst(b[1]))
      .map(([cat, list]) => `
        <div class="group">
          <h3>${esc(cat)}</h3>
          ${list.sort((a, b) => order[a.status] - order[b.status]).map((c) => `
            <div class="check">
              <span class="badge ${c.status}">${STATUS_LABEL[c.status]}</span>
              <span class="check-title">${esc(c.title)}</span>
              <p class="check-detail">${esc(c.detail)}</p>
              ${c.fix ? `<p class="check-fix">${fixHtml(c.fix)}</p>` : ""}
            </div>`).join("")}
        </div>`).join("");
    $("#report-body").innerHTML = html;

    const issues = s.fail + s.warn;
    $("#report-cta").textContent = issues ? `Get ${issues === 1 ? "this" : "these " + issues} fixed` : "Book monthly care";
    // prefill the contact form with the scanned site
    const site = document.querySelector('#contact-form [name="website"]');
    if (!site.value) site.value = r.host;

    const rep = $("#report");
    rep.hidden = false;
    rep.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  $("#scan-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = $("#scan-url").value.trim();
    const err = $("#scan-error");
    const btn = $("#scan-btn");
    err.hidden = true;
    if (!url) { err.textContent = "Enter your website address, for example yourbusiness.in."; err.hidden = false; return; }
    btn.disabled = true;
    btn.textContent = "Checking…";
    try {
      renderReport(await post("/api/scan", { url }));
    } catch (ex) {
      err.textContent = ex.message === "Failed to fetch"
        ? "Couldn't reach the scanner. Check your connection and try again; the server may take 30 seconds to wake up."
        : ex.message;
      err.hidden = false;
    } finally {
      btn.disabled = false;
      btn.textContent = "Check my website";
    }
  });

  $("#contact-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.currentTarget;
    const status = $("#contact-status");
    status.className = "full";
    if (!form.checkValidity()) {
      form.reportValidity();
      return;
    }
    const btn = form.querySelector("button");
    btn.disabled = true;
    status.textContent = "Booking…";
    try {
      await post("/api/contact", Object.fromEntries(new FormData(form)));
      form.reset();
      status.textContent = "Booked. We'll email you within one working day to fix a time.";
      status.classList.add("ok");
    } catch (ex) {
      status.textContent = ex.message === "Failed to fetch" ? "Couldn't send. Check your connection and try again." : ex.message;
      status.classList.add("err");
    } finally {
      btn.disabled = false;
    }
  });

  $("#year").textContent = new Date().getFullYear();
})();
