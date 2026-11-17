'use strict';
// Dependency-free behavioral tests: run the production script inside a small DOM.
const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
const path=require('node:path');
class Element {
  constructor(tag='div'){this.tagName=tag;this.children=[];this.dataset={};this.attributes={};this.listeners={};this._text='';this.value='';this.disabled=false;this.className='';this.parent=null;this.isConnected=true;this.classList={add:c=>{this.className+=' '+c;},remove:c=>{this.className=this.className.split(' ').filter(x=>x!==c).join(' ');},contains:c=>this.className.split(' ').includes(c)};}
  get textContent(){return this._text+this.children.map(c=>c.textContent).join('');}
  set textContent(v){this._text=String(v);this.children=[];}
  set innerHTML(v){throw new Error('Unsafe HTML insertion: '+v);}
  append(...nodes){for(const n of nodes){n.parent=this;this.children.push(n);}}
  prepend(n){n.parent=this;this.children.unshift(n);}
  replaceChildren(...nodes){this.children=[];this._text='';this.append(...nodes);}
  setAttribute(k,v){this.attributes[k]=String(v);}
  removeAttribute(k){delete this.attributes[k];}
  matches(s){if(s.startsWith('#'))return this.id===s.slice(1);if(s.startsWith('.'))return this.className.split(' ').includes(s.slice(1));const m=s.match(/^([\w-]+)?(?:\[([^=\]]+)(?:="([^"]*)")?\])?$/);if(!m)return false;if(m[1]&&m[1]!==this.tagName)return false;if(!m[2])return true;const key=m[2],value=key.startsWith('data-')?this.dataset[key.slice(5).replace(/-([a-z])/g,(_,c)=>c.toUpperCase())]:this.attributes[key]??this[key];return m[3]===undefined?value!==undefined:value===m[3];}
  querySelectorAll(s){const out=[];for(const c of this.children){if(s.split(',').some(x=>c.matches(x)))out.push(c);out.push(...c.querySelectorAll(s));}return out;}
  querySelector(s){const parts=s.split(' ');if(s.startsWith('#')&&parts.length>1){let root=this;for(const part of parts){root=root.querySelector(part);if(!root)return null;}return root;}return this.querySelectorAll(s)[0]||null;}
  closest(s){let el=this;while(el){if(el.matches(s))return el;el=el.parent;}return null;}
  addEventListener(k,fn){(this.listeners[k]??=[]).push(fn);}
  focus(){this.document.activeElement=this;}
  remove(){if(this.parent)this.parent.children=this.parent.children.filter(x=>x!==this);}
  async fire(k,extra={}){const e={target:this,preventDefault(){},...extra};for(const fn of this.listeners[k]||[])await fn(e);}
}
function setup(handler=()=>({})){
  const document=new Element('document');document.createElement=tag=>{const el=new Element(tag);el.document=document;return el;};
  const ids=['content','notice','dashboard','login-panel','logout','login-form','password','tabs','refresh','reauth-dialog','reauth-form','reauth-password','reauth-cancel'];
  for(const id of ids){const e=document.createElement(id.includes('form')?'form':id.includes('password')?'input':'div');e.id=id;if(['dashboard','login-panel','logout','reauth-dialog'].includes(id))e.className='hidden';document.append(e);}
  const $=s=>document.querySelector(s);
  for(const form of ['login-form','reauth-form']){const b=document.createElement('button');b.type='submit';$( '#'+form).append(b);}
  const calls=[];const context={document,Headers,FormData,AbortController,DOMException,URL,setTimeout,clearTimeout,console,location:{reload(){}},window:{addEventListener(){},confirm(){return true;},location:{assign(){}}},fetch:async(url,opts={})=>{calls.push({url,...opts});const result=await handler(url,opts);return {status:result.status||200,ok:!result.status||result.status<400,json:async()=>result.ok===false?result:{ok:true,data:result.data??result}};}};
  const filename=path.join(__dirname,'../dashboard/static/app.js');
  const source=fs.readFileSync(filename,'utf8').replace('  bootstrap();','  globalThis.ui={app,render,listFiles,request,bootstrap,loadStatus,telemetryCards,fileEntryPath,pollOperation,pause,stopPoll};');
  vm.runInNewContext(source,context,{filename});
  const ui=context.ui;ui.app.status={services:{},config_revision:7};ui.app.viewAbort=new AbortController();
  return {ui,$,document,calls,click:async b=>{$('#content').append(...(b.parent?[]:[b]));await $('#content').fire('click',{target:b});},flush:()=>new Promise(resolve=>setImmediate(resolve))};
}
function action(h,name){return h.$('#content').querySelector(`[data-action="${name}"]`);}
test('service settings PATCH integer revision instead of lifecycle POST',async()=>{
 const h=setup(url=>url==='/api/status'?{services:{web:{state:'stopped',pending_config:{port:8081,bind_address:'127.0.0.1'}}},config_revision:8}:{});
 h.ui.app.tab='services';h.ui.app.services=[{id:'web',state:'stopped',pending_config:{port:8080,bind_address:'127.0.0.1'},config_revision:7}];h.ui.render();await h.click(action(h,'service-config'));
 const req=h.calls.find(c=>c.url==='/api/services/web/config');assert.equal(req.method,'PATCH');assert.equal(JSON.parse(req.body).config_revision,7);assert.equal(h.calls.some(c=>c.url.endsWith('/service-config')),false);
});
test('nested files use listing directory for every file action and paginate',async()=>{
 const h=setup(url=>({path:'nested',entries:[{name:'<b>same.txt</b>',type:'file'},{name:'child',type:'directory'}],next_offset:url.includes('offset=0')?2:null}));
 h.ui.app.tab='files';h.ui.app.filePath='nested';h.ui.render();await h.flush();
 assert.equal(action(h,'files-delete').dataset.path,'nested/<b>same.txt</b>');assert.equal(action(h,'files-open').dataset.path,'nested/child');assert.match(h.$('#file-list').querySelector('a').href,/nested%2F%3Cb%3E/);assert.ok(h.$('#file-list').textContent.includes('<b>same.txt</b>'));
 await h.click(action(h,'files-more'));assert.ok(h.calls.some(c=>c.url.includes('offset=2')));assert.equal(action(h,'files-more'),null);
});
test('Git repositories use repos field; untrusted names remain text',async()=>{
 const h=setup(url=>url.includes('/repos')?{repos:[{name:'<img onerror=bad>'}]}:{keys:[]});h.ui.app.tab='git';h.ui.render();await h.flush();assert.ok(h.$('#content').textContent.includes('<img onerror=bad>'));assert.ok(action(h,'repo-create'));
});
test('Doctor fetches diagnostics and displays evidence',async()=>{
 const h=setup(()=>({checks:[{id:'runtime',state:'PASS',evidence:'Measured',remediation:'Remedy'}]}));h.ui.app.tab='doctor';h.ui.render();await h.flush();assert.equal(h.calls[0].url,'/api/doctor');assert.match(h.$('#content').textContent,/Measured/);
});
test('telemetry uses actual structured fields',()=>{
 const h=setup();const cards=h.ui.telemetryCards({storage:{available:true,free_mb:123},memory:{available:true,used_pct:42},battery:{available:false},network:{lan_ip:'192.0.2.1'},wake_lock:{state:'requested',held:null},environment:'mock'});
 assert.equal(cards[0][1],'123 MiB free');assert.equal(cards[1][1],'42% used');assert.equal(cards[2][1],'Unavailable');assert.equal(cards[4][2],'OS held: unknown');
});
test('tunnel targets require web/api, ownership, readiness and publication permission; reauth preserves target',async()=>{
 const h=setup(url=>url==='/api/reauth'?{}:url==='/api/status'?{services:{},config_revision:7}:{});h.ui.app.tab='tunnel';h.ui.app.services=[{id:'ssh',running:true,ready:true,owned:true,publication_allowed:true},{id:'api',running:true,ready:false,owned:true,publication_allowed:true},{id:'web',running:true,ready:true,owned:true,publication_allowed:true}];h.ui.render();const select=h.$('#content').querySelector('select');assert.equal(select.children.length,1);assert.equal(select.children[0].value,'web');select.value='web';h.$('#tunnel-ack').checked=true;await h.click(action(h,'tunnel-start'));assert.equal(h.calls.length,0);assert.equal(h.$('#reauth-dialog').classList.contains('hidden'),false);h.$('#reauth-password').value='secret';await h.$('#reauth-form').fire('submit',{submitter:h.$('#reauth-form').querySelector('button')});const call=h.calls.find(c=>c.url==='/api/tunnel/start');assert.equal(JSON.parse(call.body).target_service,'web');
});
test('authenticated bootstrap enters dashboard; expired session obtains fresh CSRF and retains typed password',async()=>{
 let expired=false;const h=setup(url=>url==='/api/session'?{authenticated:!expired,csrf_token:expired?'fresh':'existing'}:url==='/api/status'&&expired?{status:401,ok:false,error:{code:'unauthenticated',message:'expired'}}:{services:{},config_revision:7});await h.ui.bootstrap();assert.equal(h.$('#dashboard').classList.contains('hidden'),false);expired=true;h.$('#password').value='retained';await assert.rejects(h.ui.request('/api/status'),e=>e.code==='session_expired');assert.equal(h.ui.app.csrf,'fresh');assert.equal(h.$('#password').value,'retained');assert.equal(h.$('#login-panel').classList.contains('hidden'),false);
});
test('request preserves reauth error code',async()=>{const h=setup(()=>({status:403,ok:false,error:{code:'reauth_required',message:'Confirm password'}}));await assert.rejects(h.ui.request('/api/test'),e=>e.code==='reauth_required');});
test('failed operations never report success',async()=>{const h=setup(()=>({phase:'failed',error:{message:'Controller unavailable'}}));const result=await h.ui.pollOperation('abc');assert.equal(result.phase,'failed');assert.equal(h.$('#notice').className,'notice error');assert.equal(h.$('#notice').textContent,'Controller unavailable');});
test('switching views discards stale Git response',async()=>{let resolve;const pending=new Promise(r=>resolve=r);const h=setup(()=>pending);h.ui.app.tab='git';h.ui.render();h.ui.app.tab='overview';h.ui.render();resolve({repos:[{name:'STALE'}],keys:[]});await h.flush();assert.equal(h.$('#content').textContent.includes('STALE'),false);});
test('busy action blocks duplicate submission and releases after completion',async()=>{let resolve;const h=setup(url=>url==='/api/power-policy'?new Promise(r=>resolve=r):{services:{}});h.ui.app.tab='services';h.ui.render();const b=action(h,'power-policy');b.closest('form').querySelector('select').value='manual';const one=h.click(b);await h.flush();assert.equal(b.disabled,true);await h.click(b);assert.equal(h.calls.filter(x=>x.url==='/api/power-policy').length,1);resolve({});await one;assert.equal(b.disabled,false);});
test('reauth dialog traps keyboard focus and Escape restores prior focus',async()=>{const h=setup();h.ui.app.tab='files';h.ui.render();await h.flush();const b=h.document.createElement('button');b.dataset.action='files-delete';b.dataset.path='nested/file';b.focus();await h.click(b);assert.equal(h.document.activeElement,h.$('#reauth-password'));await h.$('#reauth-dialog').fire('keydown',{key:'Escape'});assert.equal(h.$('#reauth-dialog').classList.contains('hidden'),true);assert.equal(h.document.activeElement,b);});

test('automatic reauth retries the original action after coded API rejection',async()=>{let tries=0;const h=setup(url=>url==='/api/services/web/start'&&++tries===1?{status:403,ok:false,error:{code:'reauth_required',message:'Check password'}}:url==='/api/status'?{services:{}}:{});h.ui.app.tab='services';h.ui.app.services=[{id:'web',state:'stopped'}];h.ui.render();await h.click(action(h,'service-start'));assert.equal(h.$('#reauth-dialog').classList.contains('hidden'),false);h.$('#reauth-password').value='password';await h.$('#reauth-form').fire('submit',{submitter:h.$('#reauth-form').querySelector('button')});assert.equal(h.calls.filter(c=>c.url==='/api/services/web/start').length,2);});
test('jobs expose cancellation before operation polling and render output field',async()=>{const h=setup(url=>url==='/api/jobs'?{jobs:[{id:'fixed'}]}:url.endsWith('/runs')?{operation_id:'run1'}:url.startsWith('/api/operations/')?{phase:'running'}:url.endsWith('/cancel')?{state:'cancelled'}:{state:'succeeded',output:'bounded stdout and stderr',exit_code:0});h.ui.app.tab='jobs';h.ui.render();await h.flush();await h.click(action(h,'job-run'));assert.ok(action(h,'job-cancel'));await h.click(action(h,'job-result'));assert.match(h.$('#content').textContent,/bounded stdout and stderr/);await h.click(action(h,'job-cancel'));assert.match(h.$('#notice').textContent,/cancelled/);h.ui.stopPoll();});
test('stale job output is ignored after a tab switch',async()=>{let done;const h=setup(url=>url==='/api/jobs'?{jobs:[{id:'fixed'}]}:url.endsWith('/runs')?{id:'run1'}:new Promise(r=>done=r));h.ui.app.tab='jobs';h.ui.render();await h.flush();await h.click(action(h,'job-run'));const pending=h.click(action(h,'job-result'));await h.flush();h.ui.app.tab='overview';h.ui.render();done({state:'succeeded',output:'STALE JOB'});await pending;assert.equal(h.$('#content').textContent.includes('STALE JOB'),false);});
test('unsupported file management exposes a reason instead of active controls',()=>{const h=setup();h.ui.app.status.capabilities={files:{available:false,reason:'POSIX confinement unavailable'}};h.ui.app.tab='files';h.ui.render();assert.equal(action(h,'files-upload'),null);assert.match(h.$('#content').textContent,/POSIX confinement/);assert.equal(h.calls.length,0);});
test('power policy selects the actual server string',()=>{const h=setup();h.ui.app.status.power_policy='pocketserver-managed';h.ui.app.tab='services';h.ui.render();const options=h.$('#content').querySelector('select').children;assert.equal(options[1].selected,true);});
test('poll delay removes abort listeners after each completed wait',async()=>{const h=setup();const controller=new AbortController();let active=0;const signal={get aborted(){return controller.signal.aborted;},addEventListener(...args){active++;controller.signal.addEventListener(...args);},removeEventListener(...args){active--;controller.signal.removeEventListener(...args);}};await h.ui.pause(1,signal);await h.ui.pause(1,signal);assert.equal(active,0);});
