export async function request(path,options={}) {
 const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),60000);
 try {
  const response=await fetch(path,{...options,signal:options.signal||controller.signal});
  let value;try{value=await response.json();}catch{throw new Error(`服务响应不是 JSON（HTTP ${response.status}），请从移动端服务打开工作台。`);}
  if(!response.ok) throw new Error(typeof value.error==='string'?value.error:value.message||`请求失败：HTTP ${response.status}`);
  return value;
 } catch(error) {if(error.name==='AbortError')throw new Error('请求超时，请检查本地服务。');throw error;}
 finally{clearTimeout(timer);}
}
export const get=path=>request(path);
export const post=(path,value)=>request(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(value)});
export const upload=file=>request(`/api/apk?name=${encodeURIComponent(file.name)}`,{method:'POST',headers:{'Content-Type':'application/octet-stream'},body:file});
