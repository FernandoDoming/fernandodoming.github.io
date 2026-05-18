/**
 * Click post images to open a full-screen-style dialog enlargement.
 */
(function () {
  'use strict';

  var root = document.querySelector('.post-content');
  if (!root || typeof HTMLDialogElement === 'undefined') return;

  var dialog = document.createElement('dialog');
  dialog.className = 'noir-img-lightbox';
  dialog.setAttribute('aria-label', 'Enlarged image');

  var inner = document.createElement('div');
  inner.className = 'noir-img-lightbox-inner';

  var closeBtn = document.createElement('button');
  closeBtn.type = 'button';
  closeBtn.className = 'noir-img-lightbox-close';
  closeBtn.setAttribute('aria-label', 'Close');
  closeBtn.innerHTML = '\u2715';

  var lbImg = document.createElement('img');
  lbImg.className = 'noir-img-lightbox-img';
  lbImg.alt = '';

  inner.appendChild(closeBtn);
  inner.appendChild(lbImg);
  dialog.appendChild(inner);
  document.body.appendChild(dialog);

  function lockScroll(lock) {
    document.documentElement.style.overflow = lock ? 'hidden' : '';
  }

  dialog.addEventListener('close', function () {
    lockScroll(false);
    lbImg.removeAttribute('srcset');
    lbImg.removeAttribute('sizes');
  });

  function openLightbox(thumb) {
    lbImg.alt = thumb.getAttribute('alt') || '';
    lbImg.decoding = 'async';
    var srcset = thumb.getAttribute('srcset');
    if (srcset) {
      lbImg.setAttribute('srcset', srcset);
      lbImg.setAttribute('sizes', '96vw');
    } else {
      lbImg.removeAttribute('srcset');
      lbImg.removeAttribute('sizes');
    }
    lbImg.src = thumb.currentSrc || thumb.getAttribute('src') || '';

    lockScroll(true);
    dialog.showModal();
    closeBtn.focus({ preventScroll: true });
  }

  function closeLightbox() {
    if (!dialog.open) return;
    dialog.close();
  }

  closeBtn.addEventListener('click', closeLightbox);

  dialog.addEventListener('click', function (e) {
    if (e.target === dialog) closeLightbox();
  });

  lbImg.addEventListener('click', closeLightbox);

  root.addEventListener(
    'click',
    function (e) {
      var thumb = e.target.closest && e.target.closest('img');
      if (!thumb || !root.contains(thumb)) return;
      e.preventDefault();
      e.stopPropagation();
      openLightbox(thumb);
    },
    true
  );
})();
