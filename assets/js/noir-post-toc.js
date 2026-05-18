/**
 * Sidebar table of contents from h2–h4 in .post-content (nested by level).
 */
(function () {
  'use strict';

  if (document.body.classList.contains('no-toc')) return;

  var root = document.querySelector('.post-content');
  var mount = document.getElementById('post-toc');
  var nav = mount && mount.querySelector('.aside-toc-nav');
  if (!root || !mount || !nav) return;

  var candidates = root.querySelectorAll('h2, h3, h4');
  var headings = [];
  for (var i = 0; i < candidates.length; i++) {
    var h = candidates[i];
    if (h.closest('.highlight, .highlighter-rouge, pre, code')) continue;
    headings.push(h);
  }

  if (!headings.length) return;

  function slugify(text) {
    var s = text
      .trim()
      .toLowerCase()
      .replace(/[`'".,/#!$%^&*;:{}=_`~()[\]|\\<>?]/g, '')
      .replace(/\s+/g, '-')
      .replace(/-+/g, '-')
      .replace(/^-|-$/g, '');
    return s || 'section';
  }

  function ensureId(el) {
    if (el.id) return el.id;
    var base = slugify(el.textContent || '');
    var id = base;
    var n = 1;
    while (document.getElementById(id)) {
      id = base + '-' + ++n;
    }
    el.id = id;
    return id;
  }

  var rootUl = document.createElement('ul');
  rootUl.className = 'aside-toc-list';

  /** @type {{ level: number, ul: HTMLUListElement }[]} */
  var stack = [{ level: 1, ul: rootUl }];

  for (var j = 0; j < headings.length; j++) {
    var heading = headings[j];
    var level = parseInt(heading.tagName.charAt(1), 10);
    if (level < 2 || level > 6) continue;

    ensureId(heading);

    while (stack.length > 1 && stack[stack.length - 1].level >= level) {
      stack.pop();
    }

    var parentUl = stack[stack.length - 1].ul;
    var li = document.createElement('li');
    li.className = 'aside-toc-item aside-toc-level-' + level;

    var a = document.createElement('a');
    a.href = '#' + heading.id;
    a.textContent = heading.textContent.replace(/\s+/g, ' ').trim();

    li.appendChild(a);
    parentUl.appendChild(li);

    var childUl = document.createElement('ul');
    childUl.className = 'aside-toc-list';
    li.appendChild(childUl);
    stack.push({ level: level, ul: childUl });
  }

  function pruneEmptyUls(ul) {
    var children = ul.children;
    for (var c = children.length - 1; c >= 0; c--) {
      var child = children[c];
      if (child.tagName !== 'LI') continue;
      var nested = child.querySelector(':scope > ul');
      if (nested) {
        pruneEmptyUls(nested);
        if (!nested.children.length) nested.remove();
      }
    }
  }

  pruneEmptyUls(rootUl);

  nav.appendChild(rootUl);
  mount.removeAttribute('hidden');
})();
