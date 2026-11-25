; Anubis Automation Script Signer installer hooks (Tauri NSIS, current-user install).
; Put the install folder on the user's PATH so `anubisauto-signer` (the
; command-line tool installed next to the app) works in a new terminal, and
; take it off again on uninstall. PowerShell edits the value so a long PATH is
; never truncated by NSIS's string limit; nothing else in PATH is touched.
; (NSIS strings here are delimited by backticks; $$ is a literal $.)

!macro NSIS_HOOK_POSTINSTALL
  nsExec::ExecToLog `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$d = '$INSTDIR'; $$p = [Environment]::GetEnvironmentVariable('Path', 'User'); if (-not $$p) { $$p = '' }; $$parts = @($$p.Split(';') | Where-Object { $$_ -ne '' }); if ($$parts -notcontains $$d) { [Environment]::SetEnvironmentVariable('Path', (($$parts + $$d) -join ';'), 'User') }"`
  Pop $0
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::ExecToLog `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$d = '$INSTDIR'; $$p = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($$p) { $$parts = @($$p.Split(';') | Where-Object { $$_ -ne '' -and $$_ -ne $$d }); [Environment]::SetEnvironmentVariable('Path', ($$parts -join ';'), 'User') }"`
  Pop $0
!macroend
