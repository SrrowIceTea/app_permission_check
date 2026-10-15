const paths = {
 grid:'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
 scan:'M4 8V4h4 M16 4h4v4 M20 16v4h-4 M8 20H4v-4 M7 12h10',
 pulse:'M3 12h4l3-7 4 14 3-7h4', book:'M3 4h7l2 2 2-2h7v15h-7l-2 2-2-2H3z M12 6v15',
 report:'M6 3h9l4 4v14H6z M14 3v5h5 M9 12h7 M9 16h7',
 upload:'M12 16V3 M7 8l5-5 5 5 M4 15v6h16v-6',
 arrow:'M5 12h14 M13 6l6 6-6 6', search:'M10 17a7 7 0 1 0 0-14 7 7 0 0 0 0 14 M15 15l6 6',
 shield:'M12 3l8 3v6c0 5-8 9-8 9s-8-4-8-9V6z M8 12l3 3 5-6',
 file:'M6 3h9l4 4v14H6z M14 3v5h5', check:'M5 12l4 4L19 6',
 clock:'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18 M12 7v5l3 2',
 code:'M8 6l-6 6 6 6 M16 6l6 6-6 6 M14 3l-4 18',
 close:'M6 6l12 12 M6 18L18 6', link:'M10 13l4-4 M8 16l-1 1a4 4 0 0 1-6-6l4-4a4 4 0 0 1 6 0 M16 8l1-1a4 4 0 0 1 6 6l-4 4a4 4 0 0 1-6 0',
};
export function h(tag, attrs={}, ...children) {
 const el=document.createElement(tag);
 for(const [key,val] of Object.entries(attrs)) {
  if(val===null || val===undefined || val===false) continue;
  if(key==='class') el.className=val;
  else if(key==='text') el.textContent=String(val);
  else if(key.startsWith('on')) el.addEventListener(key.slice(2).toLowerCase(),val);
  else if(key in el && !key.startsWith('aria-') && key!=='role') el[key]=val;
  else el.setAttribute(key,String(val));
 }
 for(const child of children.flat(Infinity)) if(child!==null && child!==undefined && child!==false) el.append(child instanceof Node?child:document.createTextNode(String(child)));
 return el;
}
export function icon(name,cls='') {
 const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
 for(const [k,v] of Object.entries({viewBox:'0 0 24 24',fill:'none',stroke:'currentColor','stroke-width':'1.6','stroke-linecap':'round','stroke-linejoin':'round','aria-hidden':'true',class:`icon ${cls}`})) svg.setAttribute(k,v);
 const path=document.createElementNS(svg.namespaceURI,'path');path.setAttribute('d',paths[name]||paths.file);svg.append(path);return svg;
}
export function button(label,action,style='secondary',name=null) {
 return h('button',{class:`button ${style}`,type:'button',onclick:action},name?icon(name):null,label);
}
export const stateLabels={done:'已完成',running:'运行中',queued:'排队中',failed:'失败',blocked:'不可用',partial:'部分可用',not_requested:'未执行',not_run:'未运行',not_probed:'未探测',cancelled:'已取消',denied:'被拒绝',error:'调用异常',call_only:'仅调用',unknown:'待核实',obtained:'已取得',empty:'空返回',ok:'正常',candidate:'候选',possible:'可能',confirmed:'证据确认',high:'高',medium:'中',low:'低',critical:'严重'};
export function badge(state,label=null) {return h('span',{class:`badge ${['done','ok','obtained'].includes(state)?'green':['failed','high','critical'].includes(state)?'red':['partial','candidate','running','medium','unknown'].includes(state)?'amber':'neutral'}`},label||stateLabels[state]||state||'未知');}
export function header(kicker,title,description,actions=[]) {return h('div',{class:'page-heading'},h('div',{},h('div',{class:'eyebrow'},kicker),h('h1',{},title),h('p',{},description)),h('div',{class:'heading-actions'},actions));}
export function empty(title,description,name='file',action=null) {return h('div',{class:'empty-state'},h('span',{class:'empty-icon'},icon(name)),h('h3',{},title),h('p',{},description),action);}
export function panel(title,subtitle,body,actions=null) {return h('section',{class:'panel'},h('div',{class:'panel-heading'},h('div',{},h('h2',{},title),subtitle?h('p',{},subtitle):null),actions),body);}
export function metric(label,value,note,name) {return h('div',{class:'metric'},h('div',{class:'metric-top'},h('span',{},label),icon(name)),h('div',{class:'metric-value'},value===null||value===undefined?'—':value),h('p',{},note));}
export function keyvalues(pairs) {return h('dl',{class:'keyvalues'},pairs.map(([k,v])=>[h('dt',{},k),h('dd',{},v===null||v===undefined||v===''?'未提供':typeof v==='object'?JSON.stringify(v):v)]));}
export function json(value) {return h('pre',{class:'json-block',tabIndex:0},JSON.stringify(value,null,2));}
export function date(value) {if(value===null||value===undefined||value==='')return '时间未提供';const d=new Date(value);return Number.isNaN(+d)?value:d.toLocaleString('zh-CN',{hour12:false});}
export function toast(message,error=false) {const node=h('div',{class:`toast ${error?'toast-error':''}`,role:error?'alert':'status'},icon(error?'close':'check'),message);document.querySelector('#toast-region').append(node);setTimeout(()=>node.remove(),6000);}
export function safeList(value) {return Array.isArray(value)?value:[];}
export function tabs(items,onChange,selected) {return h('div',{class:'tabs',role:'tablist'},items.map(([id,label])=>h('button',{class:id===selected?'tab active':'tab',role:'tab','aria-selected':id===selected,onclick:()=>onChange(id)},label)));}
export function table(columns,rows,renderer) {return h('div',{class:'table-scroll'},h('table',{},h('thead',{},h('tr',{},columns.map(x=>h('th',{scope:'col'},x)))),h('tbody',{},rows.map(renderer))));}
