# PC Executor tool schema

Input is one JSON object per line. request_id is optional; dry_run can override the process default for one request.

~~~json
{"request_id":"uuid","action":"windows.list","params":{},"dry_run":true}
~~~

Supported MVP actions:

| Action | Params | Notes |
|---|---|---|
| screenshot.capture | {} | Returns base64 PNG. |
| windows.list | {} | Visible top-level windows. |
| uia.inspect | {"query": ElementQuery} | Accessibility inspection. |
| uia.invoke | {"query": ElementQuery} | Preferred button/menu activation. |
| uia.focus | {"query": ElementQuery} | Deterministic focus. |
| uia.set_value | {"query": ElementQuery,"value":"...","sensitive":false} | Rejects password/sensitive entry. |
| mouse.click | {"x":1,"y":2,"button":"left"} | Fallback; disabled by default. |
| keyboard.press | {"key":"enter"} | Single key. |
| keyboard.type_text | {"text":"...","sensitive":false} | Sensitive entry rejected. |
| clipboard.get | {} | Reads current text clipboard. |
| clipboard.set | {"text":"...","sensitive":false} | Sensitive entry rejected. |
| shell.run | {"argv":["git","status"],"cwd":"C:\\work"} | argv-only safe allowlist. |

ElementQuery supports automation_id, name, control_type, class_name, and window_title. Integrators should prefer automation_id, then stable name/control type, and only request coordinate fallback after a fresh screenshot if deterministic accessibility selectors are unavailable.

Result shape:

~~~json
{
  "request_id":"uuid",
  "action":"uia.invoke",
  "ok":true,
  "status":"completed",
  "started_at":"...Z",
  "finished_at":"...Z",
  "data":{},
  "error":null,
  "dry_run":false
}
~~~
