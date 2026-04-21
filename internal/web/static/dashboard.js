// Dashboard enhancements: sortable columns + live "last checked" timer.
// No framework, no deps — vanilla DOM so the page stays fast.

(function () {
  'use strict';

  // --- Sortable table ------------------------------------------------------
  // Each <th> opts in via data-sort="string|number". Each <td> can override
  // the sort key via data-sort-value=""; otherwise textContent is used.
  document.querySelectorAll('table.sortable').forEach(function (table) {
    var headers = table.querySelectorAll('thead th[data-sort]');
    headers.forEach(function (th, idx) {
      th.classList.add('sort-clickable');
      th.addEventListener('click', function () {
        var dir = th.getAttribute('aria-sort') === 'ascending' ? 'descending' : 'ascending';
        // Reset siblings.
        headers.forEach(function (other) {
          if (other !== th) other.removeAttribute('aria-sort');
        });
        th.setAttribute('aria-sort', dir);
        sortTable(table, idx, th.getAttribute('data-sort'), dir === 'ascending');
      });
    });
  });

  function sortTable(table, columnIdx, kind, asc) {
    var tbody = table.tBodies[0];
    if (!tbody) return;
    var rows = Array.prototype.slice.call(tbody.rows);
    rows.sort(function (a, b) {
      var av = cellValue(a.cells[columnIdx]);
      var bv = cellValue(b.cells[columnIdx]);
      if (kind === 'number') {
        var an = parseFloat(av); if (isNaN(an)) an = -Infinity;
        var bn = parseFloat(bv); if (isNaN(bn)) bn = -Infinity;
        return asc ? an - bn : bn - an;
      }
      av = String(av).toLowerCase();
      bv = String(bv).toLowerCase();
      if (av < bv) return asc ? -1 : 1;
      if (av > bv) return asc ? 1 : -1;
      return 0;
    });
    // Detach + re-append in new order. Browsers optimise this; no reflow
    // storm for the typical homelab fleet (<100 rows).
    var frag = document.createDocumentFragment();
    rows.forEach(function (r) { frag.appendChild(r); });
    tbody.appendChild(frag);
  }

  function cellValue(cell) {
    if (!cell) return '';
    var v = cell.getAttribute('data-sort-value');
    return v !== null ? v : cell.textContent.trim();
  }

  // --- Live "last checked" timer ------------------------------------------
  // The server rendered an initial "Xm ago" string. Every 10s we overwrite
  // it with a freshly-computed one from the epoch we embedded in
  // data-last-checked-unix. Avoids needing to reload the page just to see
  // the timer tick.
  var wrap = document.querySelector('.last-checked[data-last-checked-unix]');
  if (wrap) {
    var ts = parseInt(wrap.getAttribute('data-last-checked-unix'), 10);
    var label = wrap.querySelector('.js-last-checked');
    if (ts > 0 && label) {
      var tick = function () { label.textContent = humanAgo(ts); };
      setInterval(tick, 10000);
    }
  }

  function humanAgo(epochSeconds) {
    var d = Math.max(0, Math.floor(Date.now() / 1000 - epochSeconds));
    if (d < 60) return 'just now';
    if (d < 3600) return Math.floor(d / 60) + 'm ago';
    if (d < 48 * 3600) return Math.floor(d / 3600) + 'h ago';
    return Math.floor(d / 86400) + 'd ago';
  }
})();
