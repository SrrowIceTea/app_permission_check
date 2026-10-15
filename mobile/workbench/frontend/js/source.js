import {get} from './api.js';
import {h,button,empty,panel,json,safeList,toast} from './ui.js';
export async function renderSource(task){
 const container=h('div',{},empty('源码按需加载','反编译阶段完成后可查看文件树；未反编译不影响静态候选查看。','code',button('加载源码树',load,'secondary','code')));
 async function load(){
  container.replaceChildren(h('div',{class:'loading'},'读取源码文件树…'));
  try {
   const data=await get(`/api/tasks/${task.id}/tree`);const files=safeList(data.files);
   if(!files.length){container.replaceChildren(empty('尚无反编译源码',data.reason||'JADX 尚未运行、未完成或不可用。','code'));return;}
   const list=h('div',{class:'source-files'});const code=h('pre',{class:'source-code',tabIndex:0},'选择左侧文件查看源码。');
   async function show(file,node){
    list.querySelectorAll('.active').forEach(e=>e.classList.remove('active'));node.classList.add('active');code.textContent='正在读取…';
    try{const value=await get(`/api/tasks/${task.id}/source?path=${encodeURIComponent(file.path)}`);code.textContent=`// ${value.path || file.path}${value.truncated?'（显示内容已截断）':''}\n\n${value.text||''}`;}catch(error){code.textContent=error.message;}
   }
   let filter='';function draw(){list.replaceChildren(...files.filter(f=>f.path.toLowerCase().includes(filter.toLowerCase())).slice(0,2000).map(file=>{const node=h('button',{class:'source-file',title:file.path},file.path);node.addEventListener('click',()=>show(file,node));return node;}));}
   draw();container.replaceChildren(h('div',{class:'toolbar'},h('input',{class:'filter',type:'search',placeholder:'过滤源码路径','aria-label':'过滤源码路径',oninput:e=>{filter=e.target.value;draw();}}),h('small',{},`${files.length} 个文件 · 每次最多显示 2000 项`)),h('div',{class:'source-layout'},list,code));
  }catch(error){container.replaceChildren(empty('源码树不可用',error.message,'code',button('重试',load)));}
 }
 return panel('源码证据','纯文本安全渲染 · 文件路径与原始引用',container);
}
