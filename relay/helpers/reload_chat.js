const conv = process.argv[2];
const CDP = 'http://127.0.0.1:17410';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function main() {
  const tabs = await (await fetch(CDP + '/json/list')).json();
  const tab = tabs.find(t => String(t.url || '').includes(conv));
  if (!tab) throw new Error('target_not_found');

  const ws = new WebSocket(tab.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  let nextId = 1;
  const pending = new Map();
  ws.onmessage = event => {
    const message = JSON.parse(event.data);
    if (message.id && pending.has(message.id)) {
      pending.get(message.id)(message);
      pending.delete(message.id);
    }
  };
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, message => message.error ? reject(new Error(message.error.message)) : resolve(message.result));
    ws.send(JSON.stringify({ id, method, params }));
    setTimeout(() => { if (pending.delete(id)) reject(new Error('cdp_timeout')); }, 7000);
  });

  await send('Page.enable');
  await send('Page.reload', { ignoreCache: false });
  await sleep(8000);

  const expr = `(() => {
    const visible = el => !!(el && el.offsetParent !== null);
    const buttons=[...document.querySelectorAll('button')].filter(visible);
    const stop=buttons.some(b=>{const t=((b.getAttribute('aria-label')||'')+' '+(b.textContent||'')).toLowerCase();return t.includes('stop response')||t.includes('stop generating')||t.includes('останов');});
    const retry=buttons.some(b=>{const t=((b.getAttribute('aria-label')||'')+' '+(b.textContent||'')).toLowerCase();return t.includes('повторить')||t.includes('retry')||t.includes('try again');});
    const composer=!!document.querySelector('textarea, [contenteditable="true"]');
    return {stop,retry,composer,title:document.title,tail:(document.body?.innerText||'').slice(-1200)};
  })()`;
  const after=await send('Runtime.evaluate',{expression:expr,returnByValue:true,awaitPromise:true});
  console.log(JSON.stringify(after.result?.value || {}));
  ws.close();
}

main().catch(error => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
