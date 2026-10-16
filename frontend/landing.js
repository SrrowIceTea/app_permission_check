const enterDashboard = () => {
  document.body.style.opacity = '0';
  document.body.style.transition = 'opacity 0.5s ease';
  setTimeout(() => {
    window.location.href = 'app.html';
  }, 500);
};

const enterPipeline = () => {
  document.body.style.opacity = '0';
  document.body.style.transition = 'opacity 0.5s ease';
  setTimeout(() => {
    window.location.href = 'app.html#pipeline';
  }, 500);
};

/* —— 底部状态条：装饰性 UI，仅营造「监测运行中」氛围，不代表真实审计数据 —— */
(function () {
  const statusEl = document.getElementById('status-text');
  const procsEl = document.getElementById('metric-procs');
  const eventsEl = document.getElementById('metric-events');

  const statuses = ['监测运行中', '流量采集就绪', '规则库已加载', '事件关联分析中'];
  let statusIdx = 0;
  let procs = 3;
  let events = 128;

  if (procsEl) procsEl.textContent = String(procs);
  if (eventsEl) eventsEl.textContent = String(events);

  if (statusEl) {
    setInterval(() => {
      statusIdx = (statusIdx + 1) % statuses.length;
      statusEl.textContent = statuses[statusIdx];
    }, 3000);
  }

  if (procsEl) {
    setInterval(() => {
      procs = Math.max(2, Math.min(5, procs + (Math.random() < 0.5 ? -1 : 1)));
      procsEl.textContent = String(procs);
    }, 5000);
  }

  if (eventsEl) {
    setInterval(() => {
      events += 1 + Math.floor(Math.random() * 3);
      if (events > 9999) events = 128;
      eventsEl.textContent = String(events);
    }, 1400);
  }
})();

/* —— 入场动画 —— */
/* GSAP 从 CDN 加载；网络受限时 gsap 可能不存在——跳过动画但保证页面与按钮可用 */
if (typeof gsap !== 'undefined') {
  gsap.from('.nav', {
    y: -100,
    opacity: 0,
    duration: 1,
    ease: 'power3.out'
  });

  gsap.from('.title-line', {
    y: 60,
    opacity: 0,
    duration: 1,
    stagger: 0.2,
    delay: 0.5,
    ease: 'power3.out'
  });

  gsap.from('.hero-sub', {
    y: 30,
    opacity: 0,
    duration: 0.9,
    delay: 0.9,
    ease: 'power3.out'
  });

  gsap.from('.hero-actions', {
    y: 30,
    opacity: 0,
    duration: 0.8,
    delay: 1.1,
    ease: 'power3.out'
  });

  gsap.from('.hero-visual', {
    scale: 0.8,
    opacity: 0,
    duration: 1.2,
    delay: 0.5,
    ease: 'power3.out'
  });

  gsap.from('.status-bar', {
    y: 20,
    opacity: 0,
    duration: 0.8,
    delay: 1.4,
    ease: 'power3.out'
  });
}

/* —— 兜底保护 —— */
/* GSAP 已加载但动画异常中断（如标签页休眠、虚拟时间、ticker 卡死）时，
   3 秒后强制显示所有入场元素，保证内容永远可见。 */
setTimeout(function () {
  var els = document.querySelectorAll(
    '.nav,.title-line,.hero-sub,.hero-actions,.hero-visual,.status-bar'
  );
  for (var i = 0; i < els.length; i++) {
    var el = els[i];
    if (parseFloat(getComputedStyle(el).opacity) < 0.99) {
      el.style.opacity = '1';
      el.style.transform = 'none';
    }
  }
}, 3000);

