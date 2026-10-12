/* 极小的 Java/Kotlin 词法高亮器。**自己写是为了不引外部 CDN**。
   做法是单遍扫描 + 状态机，不是正则替换——正则替换的经典坑是：字符串里出现的关键字
   会被二次着色、注释里的引号会把后面的代码整段吃掉。这里一次扫完，每个字符只被判定一次。
   只做词法层，不做语法分析——高亮只为可读性，不承担任何"分析"职责。 */
(function () {
  'use strict';

  var KW = new Set(('abstract assert boolean break byte case catch char class const continue ' +
    'default do double else enum extends final finally float for goto if implements import ' +
    'instanceof int interface long native new package private protected public return short ' +
    'static strictfp super switch synchronized this throw throws transient try void volatile ' +
    'while var fun val object when in is null true false as typealias data sealed override ' +
    'open internal suspend lateinit companion init constructor by where out').split(' '));

  // 返回 [{text, cls}]，cls 为空表示普通文本
  function tokenize(src) {
    var out = [], i = 0, n = src.length, buf = '';
    function flush() { if (buf) { out.push({ text: buf, cls: '' }); buf = ''; } }
    function push(text, cls) { flush(); out.push({ text: text, cls: cls }); }

    while (i < n) {
      var c = src[i], next = src[i + 1];

      // 块注释
      if (c === '/' && next === '*') {
        var end = src.indexOf('*/', i + 2);
        end = end === -1 ? n : end + 2;
        push(src.slice(i, end), 'tok-com');
        i = end;
        continue;
      }
      // 行注释
      if (c === '/' && next === '/') {
        var eol = src.indexOf('\n', i);
        eol = eol === -1 ? n : eol;
        push(src.slice(i, eol), 'tok-com');
        i = eol;
        continue;
      }
      // 字符串 / 字符字面量（含三引号）
      if (c === '"' || c === "'") {
        var triple = src.startsWith(c + c + c, i);
        var quote = triple ? c + c + c : c;
        var j = i + quote.length;
        while (j < n) {
          if (src[j] === '\\') { j += 2; continue; }
          if (src.startsWith(quote, j)) { j += quote.length; break; }
          j++;
        }
        push(src.slice(i, j), 'tok-str');
        i = j;
        continue;
      }
      // 注解 @Foo
      if (c === '@' && /[A-Za-z_]/.test(next || '')) {
        var m = /^@[A-Za-z_][\w.]*/.exec(src.slice(i));
        push(m[0], 'tok-ann');
        i += m[0].length;
        continue;
      }
      // 数字
      if (/[0-9]/.test(c) || (c === '.' && /[0-9]/.test(next || ''))) {
        var num = /^0[xX][0-9a-fA-F_]+|^\d[\d_]*(\.\d+)?([eE][+-]?\d+)?[fFdDlL]?/.exec(src.slice(i));
        if (num) { push(num[0], 'tok-num'); i += num[0].length; continue; }
      }
      // 标识符 / 关键字
      if (/[A-Za-z_$]/.test(c)) {
        var word = /^[A-Za-z_$][\w$]*/.exec(src.slice(i))[0];
        if (KW.has(word)) push(word, 'tok-kw'); else buf += word;
        i += word.length;
        continue;
      }
      buf += c;
      i++;
    }
    flush();
    return out;
  }

  // 渲染进一个 <code> 元素。**只用 textContent，绝不拼 innerHTML**
  function render(codeEl, source) {
    codeEl.textContent = '';
    tokenize(source).forEach(function (part) {
      if (!part.cls) { codeEl.appendChild(document.createTextNode(part.text)); return; }
      var span = document.createElement('span');
      span.className = part.cls;
      span.textContent = part.text;
      codeEl.appendChild(span);
    });
  }

  window.VSCAN_HL = { render: render, tokenize: tokenize };
})();
