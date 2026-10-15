/* teacher-page.js: token handling for the standalone board page.
 * The token arrives in the URL fragment (/teacher#t=...), which browsers never send to a
 * server or write to logs. It is moved into sessionStorage and the fragment is removed.
 * Optional #api=<https base> points the page at the Supabase board function instead.
 */
(function () {
  "use strict";
  const KEY = "im_teacher_token";
  const $ = (id) => document.getElementById(id);
  const params = new URLSearchParams(location.hash.replace(/^#/, ""));
  let token = "";
  let base = "";
  try {
    token = params.get("t") || sessionStorage.getItem(KEY) || "";
    base = (params.get("api") || sessionStorage.getItem(KEY + "_api") || "").replace(/\/+$/, "");
    if (params.get("t")) sessionStorage.setItem(KEY, token);
    if (params.get("api")) sessionStorage.setItem(KEY + "_api", base);
    if (location.hash) history.replaceState(null, "", location.pathname + location.search);
  } catch (_) { /* storage can be blocked: the token then lives for this page load only */ }
  if (base && !/^https:\/\//.test(base)) base = "";            // a remote board must be https

  const api = { board: base + "/v1/board", seat: base + "/v1/board/seat" };
  let ctl = null;

  function begin() {
    $("tb-login").classList.add("hidden");
    $("teacher-root").classList.remove("hidden");
    if (!ctl) {
      ctl = TeacherBoard.mount($("teacher-root"), {
        board: api.board, seat: api.seat,
        headers: () => ({ Authorization: "Bearer " + token }),
        onUnauthorized: reject,
      });
    }
    ctl.start();
  }

  function reject() {
    if (ctl) ctl.stop();
    token = "";
    try { sessionStorage.removeItem(KEY); } catch (_) {}
    $("teacher-root").classList.add("hidden");
    $("tb-login").classList.remove("hidden");
    $("tb-msg").textContent = "That token was not accepted.";
  }

  function submit() {
    const v = $("tb-token").value.trim();
    if (!v) return;
    token = v;
    try { sessionStorage.setItem(KEY, token); } catch (_) {}
    $("tb-token").value = "";
    $("tb-msg").textContent = "";
    begin();
  }

  $("tb-go").addEventListener("click", submit);
  $("tb-token").addEventListener("keydown", (e) => { if (e.key === "Enter") submit(); });
  if (token) begin(); else $("tb-login").classList.remove("hidden");
})();
