# PC Control on ChatGPT Plus — quick start

This is the supported setup for the current Plus workflow:

**ChatGPT -> PC Control plugin -> private GitHub relay -> PC Executor -> Windows**

## First setup

The working checkout is expected at:

`E:\pc-github-relay`

The private ChatGPT plugin is **PC Control**.

## Every time after a PC restart

1. Open `E:\pc-github-relay`.
2. Double-click **START_PC_CONTROL.cmd**.
3. When it says **PC Control relay started** or **already running**, you are done.
4. You may close that window.
5. In ChatGPT, say something like: **«через PC Control проверь мой ПК»**.

That is all.

## If ChatGPT says the PC is offline

Run **START_PC_CONTROL.cmd** again.

The launcher is idempotent: if the relay is already alive, it does not start a second copy.

## What not to do

- Do not paste passwords, API keys, recovery codes, or session secrets into relay requests.
- Do not modify or scan `E:\manhwa`; it is a protected root.
- Do not manually duplicate a command when ChatGPT says the result is still unknown. The agent must reconcile the original request first.

## Logs

Only if troubleshooting is needed:

- stdout: `E:\pc-github-relay\.pc-relay\live.stdout.log`
- stderr: `E:\pc-github-relay\.pc-relay\live.stderr.log`

Normal use does not require opening these logs.
