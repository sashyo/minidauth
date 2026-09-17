/* Small interactive illustrations for the blog. Every demo is rendered in its
   default state in the HTML, so the page reads fine without this script. */
(function () {
  "use strict";

  function press(group, btn) {
    group.querySelectorAll("button").forEach(function (b) {
      b.setAttribute("aria-pressed", String(b === btn));
    });
  }

  // A made-up but stable "ciphertext" for display only.
  function fakeSeal(text) {
    var h = 2166136261, out = "", abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (var i = 0; i < text.length; i++) { h ^= text.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; }
    for (var j = 0; j < 22; j++) { h = Math.imul(h ^ (h >>> 13), 2246822507) >>> 0; out += abc[h % 64]; }
    return "ms1:AQAAAEAAAAC" + out + "…";
  }

  /* One booking, three ways of looking at it */
  document.querySelectorAll('[data-demo="record"]').forEach(function (root) {
    var notes = {
      db: "What Postgres holds, and what a stolen backup contains. The sealed fields are ciphertext; email and location stay readable because the app looks them up and branches on them.",
      reader: "A signed-in user whose role the quorum granted. The extension opens every sealed field in one batch before the row reaches the page.",
      none: "A signed-in user without the role, or a request with no user at all. Nothing crashes: the sealed fields simply come back sealed."
    };
    var seg = root.querySelector(".seg");
    function render(view) {
      root.querySelectorAll("td.v[data-plain]").forEach(function (td) {
        var open = view === "reader";
        td.textContent = open ? td.dataset.plain : fakeSeal(td.dataset.plain);
        td.className = "v " + (open ? "opened" : "sealed");
      });
      root.querySelector(".out").textContent = notes[view];
    }
    seg.addEventListener("click", function (e) {
      var btn = e.target.closest("button");
      if (!btn) return;
      press(seg, btn);
      render(btn.dataset.view);
    });
    render(seg.querySelector('[aria-pressed="true"]').dataset.view);
  });

  /* The prefix check we removed */
  document.querySelectorAll('[data-demo="prefix"]').forEach(function (root) {
    var input = root.querySelector("input");
    var naive = root.querySelector('[data-out="naive"]');
    var naiveNote = root.querySelector('[data-note="naive"]');
    var always = root.querySelector('[data-out="always"]');
    function render() {
      var v = input.value;
      if (!v) { naive.textContent = always.textContent = "(empty, nothing stored)"; naive.className = always.className = "v"; naiveNote.textContent = ""; return; }
      if (v.indexOf("ms1:") === 0) {
        naive.textContent = v;
        naive.className = "v leak";
        naiveNote.textContent = "Stored as typed. Plaintext is now sitting in a column everyone believes is sealed.";
      } else {
        naive.textContent = fakeSeal(v);
        naive.className = "v sealed";
        naiveNote.textContent = "Sealed. Now try a value that starts with ms1:";
      }
      always.textContent = fakeSeal(v);
      always.className = "v sealed";
    }
    input.addEventListener("input", render);
    render();
  });

  /* Where the role comes from */
  document.querySelectorAll('[data-demo="roles"]').forEach(function (root) {
    var O = {
      token: {
        edit: ["Allowed", true, "Allowed from the user's next sign-in. One person with dashboard access was enough to grant it."],
        revoke: ["Still allowed", true, "The role stays in the token the user already holds, so access continues until that token expires."],
        quorum: ["No change", false, "Nothing happens until someone also writes the role into the provider's metadata, and then the user signs in again."]
      },
      grant: {
        edit: ["Refused", false, "The next request still asks minidauth, and the grant record hasn't changed. The dashboard edit doesn't count."],
        revoke: ["Refused", false, "Refused on the very next request, because the role is looked up every time rather than carried in the token."],
        quorum: ["Allowed", true, "Allowed on the next request, once enough admins have approved and the network has signed the grant."]
      }
    };
    var source = "token", scenario = "edit";
    var segs = root.querySelectorAll(".seg");
    function render() {
      var o = O[source][scenario];
      var chip = root.querySelector(".out .chip");
      chip.textContent = o[0];
      chip.className = "chip " + (o[1] ? "chip--live" : "chip--no");
      root.querySelector(".out span.why").textContent = o[2];
    }
    segs.forEach(function (seg) {
      seg.addEventListener("click", function (e) {
        var btn = e.target.closest("button");
        if (!btn) return;
        press(seg, btn);
        if (btn.dataset.source) source = btn.dataset.source;
        if (btn.dataset.scenario) scenario = btn.dataset.scenario;
        render();
      });
    });
  });
})();
