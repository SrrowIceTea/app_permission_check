const enterDashboard = () => {
  document.body.style.opacity = '0';
  document.body.style.transition = 'opacity 0.5s ease';
  setTimeout(() => {
    window.location.href = 'app.html';
  }, 500);
};

// GSAP 从 CDN 加载；网络受限时 gsap 可能不存在——跳过动画但保证页面与按钮可用
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
}

document.body.style.opacity = '0';
requestAnimationFrame(() => {
  document.body.style.transition = 'opacity 0.5s ease';
  document.body.style.opacity = '1';
});
