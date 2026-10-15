/* safe.js: the only way server text becomes HTML.
 *
 *   el.innerHTML = html`<td>${row.path}</td>`;     // row.path is escaped
 *   el.innerHTML = html`<ul>${rows.map(r => html`<li>${r.text}</li>`)}</ul>`;
 *   html`${raw("<b>trusted</b>")}`                  // only for markup you wrote
 *
 * Plain strings and arrays of plain strings are escaped, so a template converted
 * halfway shows visible text instead of running anything. It fails closed.
 * Rules: quote every attribute; never put server text inside an on* attribute or a
 * javascript: URL; use data-* attributes and addEventListener instead.
 */
(function () {
  const MAP = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" };

  class Safe {
    constructor(s) { this.s = s; }
    toString() { return this.s; }
  }

  function esc(v) {
    return String(v ?? "").replace(/[&<>"'`]/g, (c) => MAP[c]);
  }

  function part(v) {
    if (v instanceof Safe) return v.s;
    if (Array.isArray(v)) return v.map(part).join("");
    return esc(v);
  }

  function html(strings, ...vals) {
    let out = strings[0];
    for (let i = 0; i < vals.length; i++) out += part(vals[i]) + strings[i + 1];
    return new Safe(out);
  }

  function raw(s) { return new Safe(String(s)); }

  window.esc = esc;
  window.html = html;
  window.raw = raw;
})();
