/* minidauth site: copy buttons and rail highlighting. */
(function () {
  "use strict";

  document.querySelectorAll(".copy").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var pre = btn.parentElement.querySelector("pre");
      if (!pre || !navigator.clipboard) return;
      navigator.clipboard.writeText(pre.innerText.trim()).then(function () {
        btn.textContent = "Copied";
        setTimeout(function () { btn.textContent = "Copy"; }, 1400);
      });
    });
  });

  var links = Array.prototype.slice.call(document.querySelectorAll('.rail .pill[href^="#"]'));
  if (!links.length || !("IntersectionObserver" in window)) return;

  var byId = {};
  links.forEach(function (a) { byId[a.getAttribute("href").slice(1)] = a; });

  var seen = new IntersectionObserver(function (entries) {
    entries.forEach(function (e) {
      if (!e.isIntersecting) return;
      links.forEach(function (a) { a.classList.remove("is-active"); });
      if (byId[e.target.id]) byId[e.target.id].classList.add("is-active");
    });
  }, { rootMargin: "-20% 0px -65% 0px" });

  Object.keys(byId).forEach(function (id) {
    var el = document.getElementById(id);
    if (el) seen.observe(el);
  });
})();
