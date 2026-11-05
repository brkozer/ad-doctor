// Filters the check catalog table by text, category and severity.
// Runs on every page view, including instant navigation (document$ is the theme's
// page-load observable when navigation.instant is on).
function initCatalogFilter() {
  const table = document.getElementById("catalog");
  if (!table) return;
  const text = document.getElementById("cf-text");
  const cat = document.getElementById("cf-cat");
  const sev = document.getElementById("cf-sev");
  const count = document.getElementById("cf-count");
  const rows = Array.from(table.tBodies[0].rows);
  const params = new URLSearchParams(location.search);
  text.value = params.get("q") || "";
  cat.value = params.get("category") || "";
  sev.value = params.get("severity") || "";

  function apply() {
    const q = text.value.trim().toLowerCase();
    let shown = 0;
    for (const r of rows) {
      const ok =
        (!q || r.textContent.toLowerCase().includes(q)) &&
        (!cat.value || r.dataset.category === cat.value) &&
        (!sev.value || r.dataset.severity.split(" ").includes(sev.value));
      r.hidden = !ok;
      if (ok) shown++;
    }
    count.textContent = `${shown} of ${rows.length}`;
    const p = new URLSearchParams();
    if (q) p.set("q", q);
    if (cat.value) p.set("category", cat.value);
    if (sev.value) p.set("severity", sev.value);
    history.replaceState(null, "", p.toString() ? `?${p}` : location.pathname);
  }
  for (const el of [text, cat, sev]) el.addEventListener("input", apply);
  apply();
}

if (typeof document$ !== "undefined") document$.subscribe(initCatalogFilter);
else document.addEventListener("DOMContentLoaded", initCatalogFilter);
