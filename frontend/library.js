/* V-Scanner · 历史报告扇形封面流
   零构建原生实现：中心封面正对用户，两侧按距离旋转/缩小/压暗；
   切换时整组通过 CSS 3D transform 连续过渡，下一张自然回到正中。
   数据只读 #pdf-select 的 option，不新增任何数据源。 */
(function () {
  'use strict';

  function init() {
    var sel = document.getElementById('pdf-select');
    var page = document.getElementById('page-pdf-report');
    var track = document.getElementById('coverflow-track');
    var countEl = document.getElementById('shelf-count');
    var back = document.getElementById('shelf-back');
    var prev = document.getElementById('coverflow-prev');
    var next = document.getElementById('coverflow-next');
    if (!sel || !page || !track) return;

    var opts = Array.prototype.filter.call(sel.options, function (o) { return o.value; });
    var n = opts.length;
    if (!n) return;

    var active = 0;
    var cards = [];

    function span(cls, text) {
      var node = document.createElement('span');
      node.className = cls;
      if (text !== undefined) node.textContent = text;
      return node;
    }

    opts.forEach(function (opt, i) {
      var card = document.createElement('button');
      card.type = 'button';
      card.className = 'report-cover';
      card.dataset.name = opt.textContent;
      card.appendChild(span('cf-kicker', 'PDF · ARCHIVE'));
      card.appendChild(span('cf-title', opt.textContent));
      card.appendChild(span('cf-file', opt.value.split('/').pop()));
      card.appendChild(span('cf-rule'));
      card.appendChild(span('cf-index', String(i + 1).padStart(2, '0')));
      card.appendChild(span('cf-action', '打开 PDF'));
      card.addEventListener('click', function () {
        if (i !== active) {
          active = i;
          layout();
        } else {
          openActive();
        }
      });
      track.appendChild(card);
      cards.push(card);
    });

    function layout() {
      cards.forEach(function (card, i) {
        var d = i - active;
        if (n > 1) {
          if (d > n / 2) d -= n;
          if (d < -n / 2) d += n;
        }
        var ad = Math.abs(d);
        card.style.setProperty('--d', String(d));
        card.style.setProperty('--ad', String(ad));
        card.style.zIndex = String(100 - ad);
        card.classList.toggle('is-active', d === 0);
        card.setAttribute('aria-current', d === 0 ? 'true' : 'false');
        card.setAttribute('aria-label', (d === 0 ? '打开 ' : '切换到 ') + card.dataset.name);
      });
    }

    function openActive() {
      var opt = opts[active];
      if (!opt) return;
      sel.value = opt.value;
      sel.dispatchEvent(new Event('change', { bubbles: true }));
      page.dataset.state = 'reading';
    }

    function step(dir) {
      active = (active + dir + n) % n;
      layout();
    }

    if (countEl) countEl.textContent = String(n).padStart(2, '0') + ' 册';
    if (prev) prev.addEventListener('click', function () { step(-1); });
    if (next) next.addEventListener('click', function () { step(1); });
    if (back) back.addEventListener('click', function () { page.dataset.state = 'browse'; });
    if (n < 2) {
      if (prev) prev.hidden = true;
      if (next) next.hidden = true;
    }

    document.addEventListener('keydown', function (e) {
      if (!page.classList.contains('active')) return;
      var state = page.dataset.state;
      if (e.key === 'Escape' && state === 'reading') {
        page.dataset.state = 'browse';
        return;
      }
      if (state !== 'browse') return;
      if (e.key === 'ArrowLeft') { step(-1); e.preventDefault(); }
      if (e.key === 'ArrowRight') { step(1); e.preventDefault(); }
    });

    page.dataset.state = 'browse';
    layout();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
