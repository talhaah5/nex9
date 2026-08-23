(function () {
  var KEY = 'nex9_consent';
  if (localStorage.getItem(KEY)) return;

  var style = document.createElement('style');
  style.textContent =
    '.nex9-consent{position:fixed;left:0;right:0;bottom:0;z-index:100;' +
    'background:var(--bg-elevated,#16181d);border-top:1px solid var(--border,#262a31);' +
    'box-shadow:0 -4px 16px rgba(0,0,0,.12);padding:14px 20px;' +
    'display:flex;flex-wrap:wrap;gap:12px 20px;align-items:center;justify-content:space-between;' +
    'font-family:var(--font,-apple-system,sans-serif);font-size:.85rem;color:var(--text,#eceef1)}' +
    '.nex9-consent p{margin:0;color:var(--text-dim,#9aa1ac);max-width:640px}' +
    '.nex9-consent a{color:var(--accent,#818cf8)}' +
    '.nex9-consent .nex9-btns{display:flex;gap:8px;flex-shrink:0}' +
    '.nex9-consent button{font-family:inherit;font-weight:600;font-size:.85rem;padding:8px 16px;' +
    'border-radius:8px;cursor:pointer;border:1px solid var(--accent,#818cf8)}' +
    '.nex9-consent .nex9-accept{background:var(--accent,#818cf8);color:var(--accent-contrast,#14152b)}' +
    '.nex9-consent .nex9-reject{background:transparent;color:var(--text,#eceef1);border-color:var(--border,#262a31)}';
  document.head.appendChild(style);

  var bar = document.createElement('div');
  bar.className = 'nex9-consent';
  bar.innerHTML =
    '<p>We use minimal cookies for site functionality and, if you accept, to show ads. ' +
    'Tool inputs never leave your browser. See our <a href="/privacy.html">privacy policy</a>.</p>' +
    '<div class="nex9-btns">' +
    '<button type="button" class="nex9-reject">Reject</button>' +
    '<button type="button" class="nex9-accept">Accept</button>' +
    '</div>';
  document.body.appendChild(bar);

  bar.querySelector('.nex9-accept').addEventListener('click', function () {
    localStorage.setItem(KEY, 'accepted');
    bar.remove();
  });
  bar.querySelector('.nex9-reject').addEventListener('click', function () {
    localStorage.setItem(KEY, 'rejected');
    bar.remove();
  });
})();
