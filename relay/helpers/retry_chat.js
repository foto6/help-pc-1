const conv = process.argv[2];
const CDP = 'http://127.0.0.1:17410';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function main() {
  const tabs = await (await fetch(CDP + '/json/list')).json();
  const tab = tabs.find(t => String(t.url || '').includes(conv));
  if (!tab) throw new Error('target_not_found');

  const ws = new WebSocket(tab.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = reject;
  });

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
    setTimeout(() => {
      if (pending.delete(id)) reject(new Error('cdp_timeout'));
    }, 7000);
  });

  const clickExpr = `(() => {
    const visible = el => !!(el && el.offsetParent !== null);
    const buttons = [...document.querySelectorAll('button')].filter(visible);
    const retry = buttons.find(button => {
      const text = ((button.getAttribute('aria-label') || '') + ' ' + (button.textContent || '')).trim().toLowerCase();
      return text.includes('повторить') || text.includes('retry') || text.includes('try again');
    });
    const stop = buttons.some(button => {
      const text = ((button.getAttribute('aria-label') || '') + ' ' + (button.textContent || '')).toLowerCase();
      return text.includes('stop response') || text.includes('stop generating') || text.includes('останов');
    });
    if (!retry) return { clicked: false, stop, reason: 'retry_not_found' };
    const retryText = ((retry.getAttribute('aria-label') || '') + ' ' + (retry.textContent || '')).trim();
    retry.click();
    return { clicked: true, stopBefore: stop, retryText };
  })()`;

  const before = await send('Runtime.evaluate', { expression: clickExpr, returnByValue: true, awaitPromise: true });
  await sleep(5000);

  const checkExpr = `(() => {
    const visible = el => !!(el && el.offsetParent !== null);
    const buttons = [...document.querySelectorAll('button')].filter(visible);
    const stop = buttons.some(button => {
      const text = ((button.getAttribute('aria-label') || '') + ' ' + (button.textContent || '')).toLowerCase();
      return text.includes('stop response') || text.includes('stop generating') || text.includes('останов');
    });
    const retry = buttons.some(button => {
      const text = ((button.getAttribute('aria-label') || '') + ' ' + (button.textContent || '')).toLowerCase();
      return text.includes('повторить') || text.includes('retry') || text.includes('try again');
    });
    return { stop, retry, tail: (document.body?.innerText || '').slice(-1200) };
  })()`;

  const after = await send('Runtime.evaluate', { expression: checkExpr, returnByValue: true, awaitPromise: true });
  console.log(JSON.stringify({ before: before.result?.value, after: after.result?.value }));
  ws.close();
}

main().catch(error => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
