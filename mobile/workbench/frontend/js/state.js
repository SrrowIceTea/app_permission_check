export const state={health:null,tasks:[],reports:[],selected:null,view:'tasks',job:null,busy:false,error:null,devices:null,devicesObservedAt:null,deviceReason:null,deviceProbeBusy:false,workflowError:null,captureTask:null,captureOptions:{serial:'',authorized:false,permission_response:'allow',generate_report:true}};
export function selectedTask(){return state.tasks.find(t=>t.id===state.selected)||null;}
export function update(values){Object.assign(state,values);window.dispatchEvent(new Event('lab:change'));}
export function navigate(view){location.hash=view;}
export function selectTask(id,view='static'){update({selected:id});navigate(view);}
