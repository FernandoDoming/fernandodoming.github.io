/**
 * Adds collapse/expand controls to fenced code blocks in post body.
 * Most blocks start expanded; mark a block collapsed by default with:
 *   ```lang collapse   or   ```lang {.collapsed}   or   {: .collapsed} after the fence
 */
(function () {
  'use strict';

  var root = document.querySelector('.post-content');
  if (!root) return;

  function startsCollapsed(block) {
    if (block.classList.contains('collapsed') || block.classList.contains('collapse')) {
      return true;
    }
    if (block.dataset && block.dataset.collapsed === 'true') {
      return true;
    }
    var langClass = Array.prototype.find.call(block.classList, function (cls) {
      return cls.indexOf('language-') === 0;
    });
    if (langClass && /\b(?:collapse|collapsed)\b/i.test(langClass.replace(/^language-/, ''))) {
      return true;
    }
    return false;
  }

  function enhance(block) {
    if (block.closest('.code-block-wrap')) return;

    var wrap = document.createElement('div');
    wrap.className = 'code-block-wrap';

    var toolbar = document.createElement('div');
    toolbar.className = 'code-block-toolbar';

    var topBtn = document.createElement('button');
    topBtn.type = 'button';
    topBtn.className = 'code-block-toggle mono';
    topBtn.setAttribute('aria-expanded', 'true');
    topBtn.textContent = 'Collapse';

    var tray = document.createElement('div');
    tray.className = 'code-block-collapsed-tray';

    var expandBtn = document.createElement('button');
    expandBtn.type = 'button';
    expandBtn.className = 'code-block-expand-caret';
    expandBtn.setAttribute('aria-label', 'Show full code block');
    expandBtn.setAttribute('aria-hidden', 'true');
    expandBtn.tabIndex = -1;

    var caret = document.createElement('span');
    caret.className = 'code-block-caret-icon';
    caret.setAttribute('aria-hidden', 'true');
    caret.textContent = '\u25BE';

    var expandLabel = document.createElement('span');
    expandLabel.setAttribute('aria-hidden', 'true');
    expandLabel.textContent = 'Expand';

    expandBtn.appendChild(caret);
    expandBtn.appendChild(expandLabel);
    tray.appendChild(expandBtn);

    toolbar.appendChild(topBtn);
    block.parentNode.insertBefore(wrap, block);
    wrap.appendChild(toolbar);
    wrap.appendChild(block);
    wrap.appendChild(tray);

    function syncUi() {
      var collapsed = wrap.classList.contains('is-collapsed');
      topBtn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
      topBtn.textContent = collapsed ? 'Expand' : 'Collapse';
      if (collapsed) {
        expandBtn.removeAttribute('aria-hidden');
        expandBtn.tabIndex = 0;
      } else {
        expandBtn.setAttribute('aria-hidden', 'true');
        expandBtn.tabIndex = -1;
      }
    }

    topBtn.addEventListener('click', function () {
      wrap.classList.toggle('is-collapsed');
      syncUi();
    });

    expandBtn.addEventListener('click', function () {
      wrap.classList.remove('is-collapsed');
      syncUi();
      topBtn.focus();
    });

    if (startsCollapsed(block)) {
      wrap.classList.add('is-collapsed');
    }

    syncUi();
  }

  root.querySelectorAll('div.highlighter-rouge').forEach(enhance);
  root.querySelectorAll('figure.highlight').forEach(enhance);
})();
