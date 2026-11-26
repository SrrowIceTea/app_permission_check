/* Actual checked evidence presentation. No framework, fabricated score, or model HTML. */
(function (global) {
  'use strict';
  const labels = {high:'高风险',medium:'中风险',low:'低风险',none:'未检出可评分信号',
    unknown:'未知',insufficient_evidence:'证据不足',not_tested:'未检测',partial:'覆盖有限'};
  function node(tag, cls, text) {
    const n=document.createElement(tag);if(cls)n.className=cls;
    if(text!==undefined)n.textContent=String(text);return n;
  }
  function readable(value) {
    if(value==null)return '未提供';
    if(typeof value!=='object')return String(value);
    if(Array.isArray(value))return value.map(readable).join('、');
    return value.summary||value.recommendation||value.action||value.detail||value.reason||value.text||
      (value.item?[value.item,value.why,value.impact,value.how_to_resolve].filter(Boolean).join('；'):null)||value.title||JSON.stringify(value);
  }
  function model(result) {
    const risk=result.risk||{}, counts=result.counts||{};
    return {score:typeof risk.score==='number'?risk.score:null,level:labels[risk.level]||'未知',
      summary:risk.summary||'暂无已验证风险评分',coverage:risk.coverage||{},
      dimensions:(risk.dimensions||[]).map(d=>({...d,unknown:typeof d.score!=='number'})),counts};
  }
  function section(host,title) {
    const s=node('section','report-section');s.appendChild(node('h3','report-section-title',title));
    host.appendChild(s);return s;
  }
  function riskPanel(host,result) {
    const view=model(result), box=section(host,'规则风险信号分与检测覆盖（独立于 AI 评级）');
    const head=node('div','risk-heading');
    head.appendChild(node('strong','risk-number',view.score===null?'—':view.score+' / 100'));
    head.appendChild(node('span','result-badge',view.level));box.appendChild(head);
    box.appendChild(node('p','hint',view.summary));
    const list=node('div','risk-dimensions');
    view.dimensions.forEach(d=>{
      const row=node('div','risk-dimension');row.appendChild(node('span','',d.label));
      const track=node('div','risk-track');track.setAttribute('role','img');
      track.setAttribute('aria-label',d.label+'：'+(d.unknown?'未知':d.score+'分'));
      const fill=node('i',d.unknown?'unknown':'');fill.style.width=d.unknown?'100%':Math.max(0,Math.min(100,d.score))+'%';
      track.appendChild(fill);row.appendChild(track);row.appendChild(node('span','mono',d.unknown?'未知':d.score));list.appendChild(row);
    });box.appendChild(list);
    box.appendChild(node('p','hint','评分是证据支持的风险信号，不是安全认证；未知维度不按 0 分处理。'));
  }
  function list(host,title,values) {
    const s=section(host,title);
    if(!values||!values.length){s.appendChild(node('p','hint','本轮未提供此类条目'));return;}
    const ul=node('ul','audit-list');values.forEach(v=>ul.appendChild(node('li','',readable(v))));s.appendChild(ul);
  }
  function renderAI(host,entry) {
    host.textContent='';
    const data=entry.aiOutput, result=entry.fin&&entry.fin.result||{};
    if(!data||!data.stages){host.appendChild(node('p','notice','本轮尚无通过引用校验的 AI 输出；静态命中不替代 AI 研判。'));return;}
    const stages=data.stages,final=stages.stage3||{},meta=data.live_calls||{};
    const header=section(host,'本轮真实 AI 研判');
    header.appendChild(node('p','audit-intro',labels[final.overall_risk]||final.overall_risk||'证据不足'));
    header.appendChild(node('p','',final.overall_risk_reason||''));
    header.appendChild(node('p','hint',(meta.models||[]).join(' / ')+' · '+(meta.request_count||0)+' 次真实请求（含必要校验修复） · 三阶段已通过'));
    riskPanel(host,result);
    [['阶段一 · 政策声明提取','stage1','declared_collection'],['阶段二 · 实际行为一致性','stage2','per_data_type'],['阶段三 · 风险评估条目','stage3','items']].forEach(([title,key,field])=>{
      const s=section(host,title), rows=(stages[key]||{})[field]||[];
      if(!rows.length)s.appendChild(node('p','hint','无此类条目；不等于已证明没有风险'));
      rows.forEach(item=>{
        const article=node('article','evidence-row');
        article.appendChild(node('h4','',item.data_type||item.category_title||item.rule_id||item.title||item.data_type_key||item.assessment||'政策声明'));
        article.appendChild(node('p','',readable(item)));
        const details=node('details');details.appendChild(node('summary','','查看引用与完整字段'));
        details.appendChild(node('pre','evidence-json',JSON.stringify(item,null,2)));article.appendChild(details);s.appendChild(article);
      });
    });
    list(host,'整改建议',final.recommendations);list(host,'证据缺口与不确定性',final.uncertainties);
    const coverage=section(host,'覆盖说明');coverage.appendChild(node('p','',final.coverage_note||''));
    const raw=node('details','checked-json');raw.appendChild(node('summary','','查看已校验三阶段 JSON'));
    raw.appendChild(node('pre','evidence-json',JSON.stringify(stages,null,2)));host.appendChild(raw);
  }
  function renderLibrary(page,entries,base) {
    let host=page.querySelector('.current-report-library');
    if(!host){host=node('section','current-report-library');page.insertBefore(host,page.children[1]||null);}
    host.textContent='';host.appendChild(node('h3','','本轮检测报告'));
    const completed=entries.filter(e=>e.fin&&e.fin.state==='done'&&e.fin.result&&e.fin.result.report);
    if(!completed.length){host.appendChild(node('p','hint','尚无通过完整检测的本轮 PDF；下方封面为历史示例快照。'));return;}
    const table=node('table','results-table');
    const th=node('thead'),head=node('tr');['样本 / 模式','AI 请求','PDF','操作'].forEach(t=>head.appendChild(node('th','',t)));th.appendChild(head);table.appendChild(th);
    const body=node('tbody');completed.forEach(e=>{
      const r=e.fin.result,v=r.verification||{},s=v.stages||{},tr=node('tr');
      tr.appendChild(node('td','',e.name+' · '+(r.mode||'')));
      tr.appendChild(node('td','mono',(s.ai||{}).request_count||'—'));tr.appendChild(node('td','',(s.report||{}).pages+' 页'));
      const td=node('td'),a=node('a','pl-btn','打开本轮 PDF');a.href=base+'/api/pipeline/'+encodeURIComponent(e.id)+'/report';a.target='_blank';a.rel='noopener';td.appendChild(a);tr.appendChild(td);body.appendChild(tr);
    });table.appendChild(body);host.appendChild(table);
  }
  function evidenceTable(host,title,rows,columns) {
    const box=section(host,title+' · '+rows.length+' 条');
    if(!rows.length){box.appendChild(node('p','hint','本场景未观察到此类证据，不等于应用不存在此类行为。'));return;}
    const table=node('table','results-table'),head=node('thead'),tr=node('tr');
    columns.forEach(c=>tr.appendChild(node('th','',c[0])));head.appendChild(tr);table.appendChild(head);
    const body=node('tbody');rows.slice(0,50).forEach(row=>{
      const tr=node('tr');columns.forEach(c=>tr.appendChild(node('td',c[1]==='evidence_id'?'mono':'',readable(row[c[1]]))));body.appendChild(tr);
    });table.appendChild(body);box.appendChild(table);
    if(rows.length>50)box.appendChild(node('p','hint','展示前 50 条；完整证据保留在本轮 JSON。'));
    const raw=node('details');raw.appendChild(node('summary','','查看完整证据字段'));
    raw.appendChild(node('pre','evidence-json',JSON.stringify(rows,null,2)));box.appendChild(raw);
  }
  function renderDynamic(host,entry) {
    host.textContent='';const b=entry.bundleOutput,r=entry.fin.result||{},v=r.verification||{};
    const summary=section(host,'本轮实际动态证据');
    summary.appendChild(node('p','',(r.mode||'')+' · '+((v.capture||{}).source_capture?'原始会话已保留':'实际采集')));
    summary.appendChild(node('p','hint','读取 '+(b.counts.reads||0)+' · 网络流 '+(b.counts.flows||0)+' · 存储/加密观察 '+(b.counts.storage_crypto_observations||0)));
    const d=b.dynamic||{};
    evidenceTable(host,'敏感 API 读取',d.reads||[],[['证据','evidence_id'],['数据类别','data_type_zh'],['API','api'],['读取状态','collection_state'],['值数量','value_count']]);
    evidenceTable(host,'实际网络流',(b.traffic||{}).flows||[],[['证据','evidence_id'],['主机','host'],['方法','method'],['响应状态','status_code'],['归因','attribution']]);
    evidenceTable(host,'同意与权限时序',d.consent_timeline||[],[['证据','evidence_id'],['事件','ev'],['API','api']]);
    const storage=section(host,'存储与加密观察');
    storage.appendChild(node('p','hint','API 写入观察不直接证明磁盘持久化或个人信息泄露。'));
    const raw=node('details');raw.appendChild(node('summary','','查看本轮存储/加密证据'));
    raw.appendChild(node('pre','evidence-json',JSON.stringify(d.storage_crypto||{},null,2)));storage.appendChild(raw);
    list(host,'采集范围与缺口',b.gaps||[]);
    if (global.VScanTaskActions && entry.fin.state === 'done') {
      global.VScanTaskActions.reviews(section(host,'逐条人工复核'), entry, 'http://127.0.0.1:8771');
    }
    const a=node('a','pl-btn','打开本轮完整证据 JSON');a.target='_blank';a.rel='noopener';
    a.href='http://127.0.0.1:8771/api/pipeline/'+encodeURIComponent(entry.id)+'/bundle';host.appendChild(a);
  }
  global.VScanResults={model,renderAI,renderLibrary,renderDynamic};
})(typeof window==='undefined'?globalThis:window);
