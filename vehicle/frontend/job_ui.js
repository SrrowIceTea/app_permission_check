/* Existing identity and timing projection; no client-side evidence inference. */
(function () {
  'use strict';
  const U = window.VehicleUI, $ = id => document.getElementById(id);
  /* C 档任务头与耗时：只展示后端返回的字段，缺失即 — + 后端写明的缺口原因 */
  function bytes(size) {
    if (!Number.isFinite(size)) return null;
    if (size < 1024) return size + ' B';
    if (size < 1024 * 1024) return (size / 1024).toFixed(1) + ' KiB';
    return (size / 1024 / 1024).toFixed(2) + ' MiB';
  }
  function missing(raw, reason) {
    const ok = !(raw === null || raw === undefined || raw === '');
    const node = U.node('span', ok ? '' : 'field-missing', ok ? String(raw) : '—');
    if (!ok) node.title = reason;
    return node;
  }
  function fmtMs(ms) {
    if (!Number.isFinite(ms)) return null;
    return ms < 1000 ? ms + ' ms' : (ms / 1000).toFixed(1) + ' s';
  }
  function identityCell(label, node) {
    const cell = U.node('div', 'job-identity__cell');
    cell.append(U.node('span', 'job-identity__label', label), node);
    return cell;
  }
  function shaNode(job, gaps) {
    const sha = typeof job.apk_sha256 === 'string' && job.apk_sha256 ? job.apk_sha256 : null;
    if (!sha) return missing(null, gaps.apk_sha256 || '后端未返回 apk_sha256。');
    const box = U.node('details', 'job-sha');
    const brief = U.node('summary', 'job-sha__brief');
    brief.append(U.node('code', 'job-sha__short', sha.slice(0, 12)),
      U.node('span', 'job-sha__cue', '展开全量'));
    const full = U.node('div', 'job-sha__full');
    const copy = U.node('button', 'pl-btn job-sha__copy', '复制');
    copy.type = 'button';
    copy.addEventListener('click', function () {
      const done = ok => { copy.textContent = ok ? '已复制' : '复制失败'; };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(sha).then(() => done(true), () => done(false));
      } else done(false);
    });
    full.append(U.node('code', 'job-sha__code', sha), copy);
    box.append(brief, full);
    return box;
  }
  function jobIdentity(job) {
    const host = $('job-identity');
    host.replaceChildren();
    if (!job) return;
    const gaps = job.field_gaps && typeof job.field_gaps === 'object' ? job.field_gaps : {};
    const grid = U.node('div', 'job-identity__grid');
    grid.append(
      identityCell('被测包名', missing(job.package, gaps.package || '后端未返回 package。')),
      identityCell('APK 大小', missing(bytes(job.apk_size), gaps.apk_size || '后端未返回 apk_size。')),
      identityCell('SHA-256', shaNode(job, gaps)));
    const source = identityCell('哈希来源', missing(job.apk_sha256_source,
      '后端未返回 apk_sha256_source；无法确认该哈希来自产物还是服务端现场计算。'));
    source.classList.add('job-identity__cell--wide');
    grid.append(source);
    host.append(grid);
  }
  function elapsed(job) {
    const node = $('pipeline-elapsed');
    node.hidden = !job;
    const ms = job && Number.isFinite(job.stage_timings_elapsed_ms) ? job.stage_timings_elapsed_ms : null;
    node.textContent = job ? '总耗时 ' + (fmtMs(ms) || '—') : '';
    node.classList.toggle('field-missing', !!job && ms === null);
    if (job) {
      node.title = ms === null
        ? '后端未返回 stage_timings_elapsed_ms：events.jsonl 不足两条数值型时间戳。'
        : '来自后端 stage_timings_elapsed_ms（events.jsonl 首尾时间戳之差）。';
    }
  }
  U.jobIdentity = jobIdentity; U.elapsed = elapsed; U.fmtMs = fmtMs;
}());
