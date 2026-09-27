# PC Executor tool schema

Input is one JSON object per line. `request_id` is optional; `dry_run` can override the process default for one request; `timeout_ms` optionally supplies a positive per-request deadline.

~~~json
{"request_id":"uuid","action":"windows.list","params":{},"dry_run":true,"timeout_ms":5000}
~~~

## Actions

| Action | Params | Notes |
|---|---|---|
| screenshot.capture | {} | Base64 PNG plus capture id, dimensions, display geometry, coordinate space and SHA-256. |
| windows.list | {} | Visible top-level windows in deterministic order. |
| uia.snapshot | {"window_title":"optional"} | Read-only canonical UIA observation snapshot. |
| uia.inspect | {"query": ElementQuery} | Re-resolves and refreshes current metadata. |
| uia.invoke | {"query": ElementQuery} | Requires enabled/onscreen deterministic InvokePattern. |
| uia.focus | {"query": ElementQuery} | Deterministic focus after re-resolution. |
| uia.set_value | {"query": ElementQuery,"value":"...","sensitive":false} | Requires ValuePattern; rejects password/sensitive entry. |
| vision.target.invoke | {"target": vision.grounded_target.v1} | Frozen v1 contract; automation_id only; never coordinate input. |
| mouse.click | {"x":1,"y":2,"button":"left"} | Raw fallback; disabled by default, including dry-run. |
| keyboard.press | {"key":"enter"} | Bounded single-key input. |
| keyboard.type_text | {"text":"...","sensitive":false} | Bounded input; sensitive entry rejected. |
| clipboard.get | {} | Bounded text clipboard read. |
| clipboard.set | {"text":"...","sensitive":false} | Bounded write; sensitive entry rejected. |
| shell.run | {"argv":["git","status"],"cwd":"C:\\work"} | argv-only allowlist, protected paths, cancellation/deadline, bounded stdout/stderr. |

`ElementQuery` supports `automation_id`, `name`, `control_type`, `class_name`, and `window_title`. At least one non-empty selector is required and unknown keys are rejected.

## Result shape

~~~json
{
  "request_id":"uuid",
  "action":"uia.invoke",
  "ok":false,
  "status":"stale_target",
  "started_at":"...Z",
  "finished_at":"...Z",
  "data":{},
  "error":"UIA automation_id not found: save",
  "error_kind":"stale_target",
  "dry_run":false
}
~~~

`error_kind` is one of `transient`, `stale_target`, `ambiguous_target`, `policy_blocked`, `timeout`, `cancelled`, or `executor_failure`.

## Shell result metadata

Live `shell.run` additionally returns `stdout_bytes`, `stderr_bytes`, `stdout_truncated`, `stderr_truncated`, and `output_limit_bytes`. Truncation is deterministic from the beginning of each UTF-8 byte stream.

## Screenshot metadata

Live `screenshot.capture` returns `capture_id`, `width`, `height`, `coordinate_space="physical_screen_px"`, `display_geometry`, `sha256`, byte count, MIME/encoding and base64 data.

## UIA snapshot transport

`uia.snapshot` returns both a parsed `snapshot` object and `canonical_json`. Nodes carry deterministic node ids, role/name/automation id/class, enabled/offscreen state, physical bounds, display id, window/process ids and invoke/value capability flags.
