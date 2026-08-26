using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace MultiOtpManager.Core
{
    public sealed class MultiOtpCliClient
    {
        private readonly MultiOtpProcessExecutor executor;

        public MultiOtpCliClient()
        {
            string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
            string executablePath = Path.Combine(baseDirectory, "multiotp.exe");
            executor = new MultiOtpProcessExecutor(executablePath);
        }

        public string ExecutablePath
        {
            get { return executor.ExecutablePath; }
        }

        public bool UseVerifySwitch { get; set; }

        // --- Authentication ---

        public Task<ProcessRunResult> VerifyAsync(string username, string otp, TimeSpan timeout, CancellationToken ct)
        {
            ValidateRequiredText(username, "username");
            ValidateRequiredText(otp, "OTP");
            List<string> args = new List<string>();
            if (UseVerifySwitch) args.Add("-verify");
            args.Add(username);
            args.Add(otp);
            return executor.ExecuteAsync(args, timeout, ct);
        }

        // --- User Management ---

        public Task<ProcessRunResult> GetUsersAsync(TimeSpan timeout, CancellationToken ct)
        {
            return executor.ExecuteAsync(new List<string> { "-userslist" }, timeout, ct);
        }

        public Task<ProcessRunResult> GetUserAsync(string username, TimeSpan timeout, CancellationToken ct)
        {
            ValidateRequiredText(username, "username");
            return executor.ExecuteAsync(new List<string> { "-user-info", username }, timeout, ct);
        }

        public Task<ProcessRunResult> CreateUserAsync(string username, string algorithm, string seed, string pin, string digits, string interval, TimeSpan timeout, CancellationToken ct)
        {
            ValidateRequiredText(username, "username");
            List<string> args = new List<string> { "-create", username };
            if (!string.IsNullOrWhiteSpace(algorithm)) args.Add(algorithm);
            if (!string.IsNullOrWhiteSpace(seed)) args.Add(seed);
            if (!string.IsNullOrWhiteSpace(pin)) args.Add(pin);
            if (!string.IsNullOrWhiteSpace(digits)) args.Add(digits);
            if (!string.IsNullOrWhiteSpace(interval)) args.Add(interval);
            return executor.ExecuteAsync(args, timeout, ct);
        }

        public Task<ProcessRunResult> FastCreateUserAsync(string username, string pin, TimeSpan timeout, CancellationToken ct)
        {
            ValidateRequiredText(username, "username");
            List<string> args = new List<string> { "-fastcreate", username };
            if (!string.IsNullOrWhiteSpace(pin)) args.Add(pin);
            return executor.ExecuteAsync(args, timeout, ct);
        }

        public Task<ProcessRunResult> FastCreateNoPinUserAsync(string username, TimeSpan timeout, CancellationToken ct)
        {
            ValidateRequiredText(username, "username");
            return executor.ExecuteAsync(new List<string> { "-fastcreatenopin", username }, timeout, ct);
        }

        public Task<ProcessRunResult> CreateGoogleAuthUserAsync(string username, string base32Seed, string pin, TimeSpan timeout, CancellationToken ct)
        {
            ValidateRequiredText(username, "username");
            ValidateRequiredText(base32Seed, "base32 seed");
            List<string> args = new List<string> { "-createga", username, base32Seed };
            if (!string.IsNullOrWhiteSpace(pin)) args.Add(pin);
            return executor.ExecuteAsync(args, timeout, ct);
        }

        public Task<ProcessRunResult> DeleteUserAsync(string username, TimeSpan timeout, CancellationToken ct)
        {
            ValidateRequiredText(username, "username");
            return executor.ExecuteAsync(new List<string> { "-delete", username }, timeout, ct);
        }

        public Task<ProcessRunResult> ActivateUserAsync(string username, TimeSpan timeout, CancellationToken ct)
        {
            ValidateRequiredText(username, "username");
            return executor.ExecuteAsync(new List<string> { "-activate", username }, timeout, ct);
        }

        public Task<ProcessRunResult> DeactivateUserAsync(string username, TimeSpan timeout, CancellationToken ct)
        {
            ValidateRequiredText(username, "username");
            return executor.ExecuteAsync(new List<string> { "-deactivate", username }, timeout, ct);
        }

        public Task<ProcessRunResult> LockUserAsync(string username, TimeSpan timeout, CancellationToken ct)
        {
            ValidateRequiredText(username, "username");
            return executor.ExecuteAsync(new List<string> { "-lock", username }, timeout, ct);
        }

        public Task<ProcessRunResult> UnlockUserAsync(string username, TimeSpan timeout, CancellationToken ct)
        {
            ValidateRequiredText(username, "username");
            return executor.ExecuteAsync(new List<string> { "-unlock", username }, timeout, ct);
        }

        public Task<ProcessRunResult> ResyncTokenAsync(string username, string token1, string token2, TimeSpan timeout, CancellationToken ct)
        {
            ValidateRequiredText(username, "username");
            ValidateRequiredText(token1, "token1");
            ValidateRequiredText(token2, "token2");
            return executor.ExecuteAsync(new List<string> { "-resync", username, token1, token2 }, timeout, ct);
        }

        public Task<ProcessRunResult> UpdatePinAsync(string username, string pin, TimeSpan timeout, CancellationToken ct)
        {
            ValidateRequiredText(username, "username");
            ValidateRequiredText(pin, "pin");
            return executor.ExecuteAsync(new List<string> { "-update-pin", username, pin }, timeout, ct);
        }

        public Task<ProcessRunResult> SetUserAttributeAsync(string username, string attribute, string value, TimeSpan timeout, CancellationToken ct)
        {
            ValidateRequiredText(username, "username");
            ValidateRequiredText(attribute, "attribute");
            return executor.ExecuteAsync(new List<string> { "-set", username, attribute + "=" + value }, timeout, ct);
        }

        public Task<ProcessRunResult> GetLockedUsersAsync(TimeSpan timeout, CancellationToken ct)
        {
            return executor.ExecuteAsync(new List<string> { "-lockeduserslist" }, timeout, ct);
        }

        // --- Provisioning ---

        public Task<ProcessRunResult> GetUrlLinkAsync(string username, TimeSpan timeout, CancellationToken ct)
        {
            ValidateRequiredText(username, "username");
            return executor.ExecuteAsync(new List<string> { "-urllink", username }, timeout, ct);
        }

        public Task<ProcessRunResult> CreateQrCodeAsync(string username, string pngFilePath, TimeSpan timeout, CancellationToken ct)
        {
            ValidateRequiredText(username, "username");
            ValidateRequiredText(pngFilePath, "PNG file path");
            return executor.ExecuteAsync(new List<string> { "-qrcode", username, pngFilePath }, timeout, ct);
        }

        // --- Token Management ---

        public Task<ProcessRunResult> GetTokensAsync(TimeSpan timeout, CancellationToken ct)
        {
            return executor.ExecuteAsync(new List<string> { "-tokenslist" }, timeout, ct);
        }

        public Task<ProcessRunResult> AssignTokenAsync(string username, string tokenId, TimeSpan timeout, CancellationToken ct)
        {
            ValidateRequiredText(username, "username");
            ValidateRequiredText(tokenId, "token ID");
            return executor.ExecuteAsync(new List<string> { "-assign-token", username, tokenId }, timeout, ct);
        }

        public Task<ProcessRunResult> RemoveTokenAsync(string username, TimeSpan timeout, CancellationToken ct)
        {
            ValidateRequiredText(username, "username");
            return executor.ExecuteAsync(new List<string> { "-remove-token", username }, timeout, ct);
        }

        public Task<ProcessRunResult> DeleteTokenAsync(string tokenId, TimeSpan timeout, CancellationToken ct)
        {
            ValidateRequiredText(tokenId, "token ID");
            return executor.ExecuteAsync(new List<string> { "-delete-token", tokenId }, timeout, ct);
        }

        // --- Logs & Diagnostics ---

        public Task<ProcessRunResult> ShowLogAsync(TimeSpan timeout, CancellationToken ct)
        {
            return executor.ExecuteAsync(new List<string> { "-showlog" }, timeout, ct);
        }

        public Task<ProcessRunResult> ClearLogAsync(TimeSpan timeout, CancellationToken ct)
        {
            return executor.ExecuteAsync(new List<string> { "-clearlog" }, timeout, ct);
        }

        public Task<ProcessRunResult> GetErrorCodesAsync(TimeSpan timeout, CancellationToken ct)
        {
            return executor.ExecuteAsync(new List<string> { "-error-codes" }, timeout, ct);
        }

        public Task<ProcessRunResult> GetVersionAsync(TimeSpan timeout, CancellationToken ct)
        {
            return executor.ExecuteAsync(new List<string> { "-version" }, timeout, ct);
        }

        // --- AD/LDAP ---

        public Task<ProcessRunResult> LdapCheckAsync(TimeSpan timeout, CancellationToken ct)
        {
            return executor.ExecuteAsync(new List<string> { "-ldap-check" }, timeout, ct);
        }

        public Task<ProcessRunResult> LdapUsersListAsync(TimeSpan timeout, CancellationToken ct)
        {
            return executor.ExecuteAsync(new List<string> { "-ldap-users-list" }, timeout, ct);
        }

        public Task<ProcessRunResult> LdapUsersSyncAsync(TimeSpan timeout, CancellationToken ct)
        {
            return executor.ExecuteAsync(new List<string> { "-ldap-users-sync" }, timeout, ct);
        }

        public Task<ProcessRunResult> LdapUserInfoAsync(string username, TimeSpan timeout, CancellationToken ct)
        {
            ValidateRequiredText(username, "username");
            return executor.ExecuteAsync(new List<string> { "-ldap-user-info", username }, timeout, ct);
        }

        // --- Backup & Maintenance ---

        public Task<ProcessRunResult> BackupConfigAsync(string password, TimeSpan timeout, CancellationToken ct)
        {
            ValidateRequiredText(password, "password");
            return executor.ExecuteAsync(new List<string> { "-backup-config", password }, timeout, ct);
        }

        public Task<ProcessRunResult> RestoreConfigAsync(string password, TimeSpan timeout, CancellationToken ct)
        {
            ValidateRequiredText(password, "password");
            return executor.ExecuteAsync(new List<string> { "-restore-config", password }, timeout, ct);
        }

        public Task<ProcessRunResult> PurgeLockFolderAsync(TimeSpan timeout, CancellationToken ct)
        {
            return executor.ExecuteAsync(new List<string> { "-purge-lock-folder" }, timeout, ct);
        }

        public Task<ProcessRunResult> PurgeLdapCacheAsync(TimeSpan timeout, CancellationToken ct)
        {
            return executor.ExecuteAsync(new List<string> { "-purge-ldap-cache-folder" }, timeout, ct);
        }

        // --- Helpers ---

        private static void ValidateRequiredText(string value, string fieldName)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException(fieldName + " is required.", fieldName);
            }
        }
    }
}
