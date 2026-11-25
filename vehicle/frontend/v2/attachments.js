/* Optional local evidence for explicitly authorized dynamic workbench tasks. */
(function () {
  'use strict';
  const VS = window.VS, attachments = window.VehicleAttachments;
  const panel = document.createElement('details');
  panel.className = 'attachment-panel';
  panel.hidden = true;
  panel.innerHTML = '<summary>政策与场景材料（可选）</summary>' +
    '<p class="sub">选择入口 JSON 及引用文件。保留相对路径，最多 64 个文件，共 4 MiB。</p>' +
    '<fieldset class="attachment-fields">' +
    '<label class="audit-field"><span>选择文件</span><input type="file" data-field="files" multiple></label>' +
    '<label class="audit-field"><span>或选择证据文件夹</span><input type="file" data-field="folder" webkitdirectory multiple></label>' +
    '<label class="audit-field"><span>政策清单</span><select data-field="policy"><option value="">未提供</option></select></label>' +
    '<label class="audit-field"><span>场景清单</span><select data-field="scenarios"><option value="">未提供</option></select></label>' +
    '</fieldset><button class="mini-btn" type="button" data-clear>清空材料</button>';
  document.getElementById('dz').before(panel);
  const fields = Object.fromEntries(Array.from(panel.querySelectorAll('[data-field]'), input => [input.dataset.field, input]));
  const reset = attachments.bind(fields);
  const clear = panel.querySelector('[data-clear]');
  const fieldset = panel.querySelector('fieldset');
  clear.addEventListener('click', reset);

  VS.attachments = {
    setMode(mode) { panel.hidden = mode === 'static'; },
    lock(value) { fieldset.disabled = clear.disabled = value; },
    reset,
    async submit() {
      if ((fields.files.files.length || fields.folder.files.length) && !fields.policy.value && !fields.scenarios.value) {
        panel.open = true;
        throw new Error('请选择政策或场景入口 JSON，或清空已选材料。');
      }
      return attachments.submit(fields, VS.api);
    },
  };
}());
