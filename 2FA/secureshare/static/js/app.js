(function () {
  "use strict";
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var csrf = ($('meta[name="csrf-token"]') || {}).content || "";

  // Show timestamps in the viewer's local time zone.
  $$("time[data-time]").forEach(function (t) {
    var d = new Date(t.getAttribute("datetime"));
    if (!isNaN(d)) t.textContent = d.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
    t.title = t.getAttribute("datetime");
  });

  // Share form: tell the server our UTC offset so "expires at" means local time.
  $$(".tz-offset").forEach(function (i) { i.value = new Date().getTimezoneOffset(); });

  // Confirm destructive actions.
  document.addEventListener("submit", function (e) {
    var msg = e.target.getAttribute && e.target.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) e.preventDefault();
  });

  // Password strength meter (length + variety; the server enforces the real policy).
  $$("[data-strength]").forEach(function (input) {
    var meter = $(input.getAttribute("data-strength"));
    input.addEventListener("input", function () {
      var v = input.value, score = 0;
      if (v.length >= 12) score++;
      if (v.length >= 16) score++;
      if (/[a-z]/.test(v) && /[A-Z]/.test(v) || /\d/.test(v) && /[a-z]/i.test(v)) score++;
      if (/[^A-Za-z0-9]/.test(v) || v.length >= 20) score++;
      if (v.length < 12) score = Math.min(score, 1);
      meter.setAttribute("data-level", v ? Math.max(score, 1) : 0);
      $("span", meter).textContent = v ? ["", "Too short or weak", "Okay", "Good", "Strong"][Math.max(score, 1)] : "";
    });
  });

  // Copy / download / print helpers (backup codes, share links).
  var textOf = function (sel) {
    var el = $(sel);
    return el ? $$("li", el).length ? $$("li", el).map(function (l) { return l.textContent.trim(); }).join("\n") : el.textContent.trim() : "";
  };
  document.addEventListener("click", function (e) {
    var b = e.target.closest("button");
    if (!b) return;
    if (b.hasAttribute("data-copy")) {
      navigator.clipboard.writeText(textOf(b.getAttribute("data-copy"))).then(function () {
        var old = b.textContent; b.textContent = "Copied"; setTimeout(function () { b.textContent = old; }, 1500);
      });
    } else if (b.hasAttribute("data-download")) {
      var blob = new Blob([textOf(b.getAttribute("data-download")) + "\n"], { type: "text/plain" });
      var a = document.createElement("a");
      a.href = URL.createObjectURL(blob); a.download = b.getAttribute("data-filename") || "download.txt";
      document.body.appendChild(a); a.click(); a.remove(); setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
    } else if (b.hasAttribute("data-print")) {
      window.print();
    }
  });

  // Uploads with progress.
  var zone = $("#dropzone");
  if (zone) {
    var list = $("#uploads"), picker = $("#picker"), max = parseInt(zone.dataset.max, 10), pending = 0;
    var fmt = function (n) { return n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB"; };
    var send = function (file) {
      var li = document.createElement("li"), row = document.createElement("div"), name = document.createElement("span"),
          status = document.createElement("span"), bar = document.createElement("progress");
      row.className = "row"; name.textContent = file.name + " (" + fmt(file.size) + ")"; status.textContent = "Uploading…";
      bar.max = 100; bar.value = 0; row.appendChild(name); row.appendChild(status); li.appendChild(row); li.appendChild(bar); list.prepend(li);
      var fail = function (msg, link) {
        status.textContent = msg; status.className = "err"; bar.remove();
        if (link) { var a = document.createElement("a"); a.href = link; a.textContent = " View existing file"; status.appendChild(a); }
      };
      if (file.size > max) return fail("Too large (limit " + fmt(max) + ").");
      var fd = new FormData(); fd.append("file", file);
      var xhr = new XMLHttpRequest();
      xhr.open("POST", zone.dataset.url);
      xhr.setRequestHeader("X-CSRF-Token", csrf);
      xhr.upload.onprogress = function (e) {
        if (e.lengthComputable) { bar.value = Math.round(e.loaded / e.total * 100); if (e.loaded === e.total) status.textContent = "Scanning and encrypting…"; }
      };
      xhr.onload = function () {
        var res = {}; try { res = JSON.parse(xhr.responseText); } catch (_) {}
        if (xhr.status === 201) {
          bar.value = 100; status.className = "done"; status.textContent = "Encrypted and saved. "; bar.remove();
          var a = document.createElement("a"); a.href = res.url; a.textContent = "Open"; status.appendChild(a);
          pending++; if (pending === 1) setTimeout(function () { window.location.reload(); }, 2500);
        } else fail(res.error || "Upload failed.", res.existing);
      };
      xhr.onerror = function () { fail("Network error. Try again."); };
      xhr.send(fd);
    };
    var take = function (files) { Array.prototype.forEach.call(files, send); };
    picker.addEventListener("change", function () { take(picker.files); picker.value = ""; });
    ["dragenter", "dragover"].forEach(function (n) { zone.addEventListener(n, function (e) { e.preventDefault(); zone.classList.add("over"); }); });
    ["dragleave", "drop"].forEach(function (n) { zone.addEventListener(n, function (e) { e.preventDefault(); zone.classList.remove("over"); }); });
    zone.addEventListener("drop", function (e) { take(e.dataTransfer.files); });
    zone.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); picker.click(); } });
  }
})();
