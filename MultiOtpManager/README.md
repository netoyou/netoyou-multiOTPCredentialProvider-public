# multiOTP Manager MVP

This is a WPF management client for the credential-provider build. It targets **.NET Framework 4.5.2** and has no NuGet or third-party UI dependencies.

## Build and deployment

1. Open `MultiOtpManager.csproj` in Visual Studio with the **.NET Framework 4.5.2 targeting pack** installed.
2. Build `AnyCPU`.
3. Place `MultiOtpManager.exe` and its manifest in the same directory as the full `multiotp.exe` runtime tree. At runtime the program resolves the executable with:

```csharp
Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "multiotp.exe")
```

The manifest requests `requireAdministrator`, because changing credential-provider registry values requires elevation. It declares Windows 7 and later as supported operating systems.

## Functions

- Authentication test: bundled multiOTP 5.10.2.2 uses the default check syntax `multiotp.exe username otp`. `MultiOtpCliClient.UseVerifySwitch` can be set to `true` for a CLI build that accepts `-verify username otp`.
- Users: list (`-userslist`), details (`-user-info`), create (`-fastcreate`), activate, deactivate, lock, unlock, resync (two consecutive OTP codes), delete.
- Provisioning: QR code (`-qrcode`) shown in a dialog together with the `otpauth://` URL (`-urllink`, copyable) so users can enroll their authenticator app. The temporary QR image embeds the token secret and is deleted immediately after display loading.
- Tokens: list (`-tokenslist`), assign (`-assign-token`), remove (`-remove-token`), delete (`-delete-token`).
- Logs & diagnostics: show log (`-showlog`), clear log (`-clearlog`), error codes (`-error-codes`), version (`-version`).
- AD/LDAP: connection check (`-ldap-check`), user list (`-ldap-users-list`), user sync (`-ldap-users-sync`). LDAP calls enforce a minimum 30 second timeout because directory queries can be slow.
- Credential Provider settings: `cpus_logon`, `cpus_unlock`, and `two_step_hide_otp`.
- Maintenance: encrypted backup/restore of the configuration (`-backup-config` / `-restore-config`), purge lock folder (`-purge-lock-folder`), purge LDAP cache (`-purge-ldap-cache-folder`).

Destructive operations (delete, clear log, restore, purge, LDAP sync) ask for confirmation before running. Backup and restore passwords are kept in memory only, never logged, and cleared from the input field right after the operation.

When these registry values are absent, the GUI follows the installer's `3d` default (no active multiOTP prompt for that usage scenario) rather than silently enabling 2FA.

Commands are assembled from typed argument lists and escaped with the Windows quoting rules in `MultiOtpProcessExecutor.EscapeArgument`. User-controlled text is never inserted directly into the command line. Standard output and error are decoded as UTF-8, and every CLI call supports cancellation and a configurable timeout.

No local log file is written. Sensitive detail keys such as seed, PIN, password, and secret are masked in the UI.
