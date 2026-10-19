# Copilot Test Build Workflow

Use this workflow when the user asks for a local test build.

## Output location

Put the finished binary in:

`E:\git\RealmHound\realmhound\target\release`

Use exactly one of these two names:

- `RealmHound_test.exe` by default.
- If `RealmHound_test.exe` is running/locked, overwrite `RealmHound.exe`.
- If `RealmHound.exe` is running/locked, overwrite `RealmHound_test.exe`.

Never create `_test2`, `-new`, or other suffixed binaries. If both files are
locked, wait for one to close or ask the user to close one.

## Official sounds

Test builds must include the same official sounds as the public build:

- Ensure the private official sound files are present in the active checkout at
  `realmhound/crates/realmhound/assets/sounds` (copy them from the main worktree
  if needed).
- Build with `REALMHOUND_OFFICIAL_SOUNDS=1`. Without it, `build.rs` deliberately
  rejects those files as a public-build safeguard.
- Do not commit the private sound files; they are gitignored.

## CPU usage

If the game or another CPU-sensitive app is running, throttle the build:

- Start `cargo build --release --locked` through `Start-Process`.
- Set the process priority to `Idle` before waiting on it.
- Run test suites at `Idle` priority as well when the game is running.

Example:

```powershell
$env:REALMHOUND_OFFICIAL_SOUNDS = '1'
$p = Start-Process cargo `
    -ArgumentList 'build', '--release', '--locked' `
    -WorkingDirectory 'E:\git\RealmHound-0.22.1\realmhound' `
    -PassThru -WindowStyle Hidden
$p.PriorityClass = 'Idle'
Wait-Process -Id $p.Id
```

## Handoff

Report the output path, file size, SHA-256, and confirm official sounds were
included. Run the relevant test suite before handing over the build.
