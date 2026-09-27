const targetId = process.argv[2];
const url = process.argv[3];
const CDP = 'http://127.0.0.1:17410';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function main() {
  const tabs = await (await fetch(CDP + '/json/list')).json();
  const tab = tabs.find(t => t.id === targetId);
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
    setTimeout(() => { if (pending.delete(id)) reject(new Error('cdp_timeout')); }, 8000);
  });

  await send('Page.enable');
  await send('Page.navigate', { url });
  await sleep(9000);
  const expr = `(() => ({
    url: location.href,
    title: document.title,
    composer: !!document.querySelector('textarea, [contenteditable="true"]'),
    stop: [...document.querySelectorAll('button')].some(b => {
      if (b.offsetParent === null) return false;
      const t=((b.getAttribute('aria-label')||'')+' '+(b.textContent||'')).toLowerCase();
      return t.includes('stop response')||t.includes('stop generating')||t.includes('останов');
    }),
    retry: [...document.querySelectorAll('button')].some(b => {
      if (b.offsetParent === null) return false;
      const t=((b.getAttribute('aria-label')||'')+' '+(b.textContent||'')).toLowerCase();
      return t.includes('повторить')||t.includes('retry')||t.includes('try again');
    }),
    tail: (document.body?.innerText||'').slice(-1200)
  }))()`;
  const result = await send('Runtime.evaluate',{expression:expr,returnByValue:true,awaitPromise:true});
  console.log(JSON.stringify(result.result?.value || {}));
  ws.close();
}

main().catch(error => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
