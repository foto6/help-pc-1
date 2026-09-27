# PC Executor

Safe Windows execution layer for agentic computer control.

The MVP provides screenshot capture, visible-window discovery, Windows UI Automation/accessibility-first interaction, keyboard/mouse/clipboard adapters, a constrained shell adapter, structured results, dry-run execution and audit events.

Safety baseline: no credential entry, no CAPTCHA solving, no destructive defaults, raw coordinate clicking disabled by default, and E:\manhwa is protected.

## Run

~~~powershell
py -m pip install -e ".[test]"
pytest
~~~

Dry-run JSONL service:

~~~powershell
'{"action":"windows.list","params":{}}' | pc-executor
~~~

Enable live side effects explicitly with pc-executor --live. Coordinate clicks additionally require --allow-coordinate-fallback.

See docs/ARCHITECTURE.md, docs/TOOL_SCHEMA.md, and docs/INTEGRATION_CONTRACT.md.
