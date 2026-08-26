using MultiOtpManager.Core;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace MultiOtpManager
{
    public partial class MainWindow
    {
        private readonly MultiOtpCliClient cliClient;
        private readonly CredentialProviderRegistryService registryService;
        private readonly SystemUserProbe systemUserProbe;
        private Button[] actionButtons;
        private CancellationTokenSource currentOperationCancellation;
        private bool refreshingUsers;

        public MainWindow()
        {
            InitializeComponent();
            cliClient = new MultiOtpCliClient();
            registryService = new CredentialProviderRegistryService();
            systemUserProbe = new SystemUserProbe();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            ExecutablePathText.Text = cliClient.ExecutablePath;
            ExecutablePathText.ToolTip = cliClient.ExecutablePath;
            actionButtons = new[]
            {
                VerifyButton, RefreshUsersButton, CreateUserButton,
                ActivateBtn, DeactivateBtn, LockBtn, UnlockBtn, ResyncBtn, QrCodeBtn, DisablePinBtn, DeleteUserBtn,
                RefreshTokensButton, AssignTokenBtn, RemoveTokenBtn, DeleteTokenBtn,
                ShowLogBtn, ClearLogBtn, ErrorCodesBtn, VersionBtn,
                LdapCheckBtn, LdapUsersListBtn, LdapSyncBtn,
                SaveSettingsButton, BackupBtn, RestoreBtn, PurgeLockBtn, PurgeLdapCacheBtn
            };
            LoadSettings();
        }

        // --- Authentication ---

        private async void VerifyButton_Click(object sender, RoutedEventArgs e)
        {
            string username = UsernameBox.Text.Trim();
            string otp = OtpBox.Password;
            cliClient.UseVerifySwitch = UseVerifySwitchBox.IsChecked == true;

            try
            {
                ProcessRunResult result = await RunOperationAsync(
                    "verify authentication",
                    delegate(CancellationToken token)
                    {
                        return cliClient.VerifyAsync(username, otp, GetTimeout(), token);
                    });

                ShowVerifyResult(result);
            }
            catch (ArgumentException error)
            {
                ShowVerifyFailure(error.Message);
            }
            catch (Exception error)
            {
                ShowVerifyFailure(GetSafeExceptionMessage(error));
            }
            finally
            {
                OtpBox.Password = string.Empty;
            }
        }

        // --- Users ---

        private async void RefreshUsersButton_Click(object sender, RoutedEventArgs e)
        {
            await LoadUsersAsync();
        }

        private async void CreateUserButton_Click(object sender, RoutedEventArgs e)
        {
            string username = NewUsernameBox.Text.Trim();
            if (username.Length == 0)
            {
                SetStatus("Enter a name for the new user.");
                NewUsernameBox.Focus();
                return;
            }

            // multiOTP Credential Provider only prompts users that already exist
            // as a Windows account. Warn before creating an entry for an unknown
            // name so users do not silently lose 2FA coverage.
            bool systemAccountKnown = await systemUserProbe.ExistsAnywhereAsync(username, GetTimeout(), CancellationToken.None);
            if (!systemAccountKnown)
            {
                if (!ConfirmAction(
                    "No Windows account named \"" + username + "\" was found on this machine" +
                    (IsDomainJoined() ? " or in the joined domain" : string.Empty) +
                    ". The multiOTP Credential Provider only runs after a Windows account has logged in, so this user will never be asked for an OTP until that account exists. Continue creating the multiOTP entry anyway?",
                    "User not found on this system"))
                {
                    SetStatus("User creation canceled: \"" + username + "\" does not match a Windows account.");
                    return;
                }
            }

            try
            {
                // Single-field creation maps to -fastcreatenopin: a TOTP token
                // compatible with Google Authenticator and no prefix PIN, so the
                // user can authenticate with just the 6-digit code from their app.
                ProcessRunResult result = await RunOperationAsync(
                    "create user",
                    delegate(CancellationToken token)
                    {
                        return cliClient.FastCreateNoPinUserAsync(username, GetTimeout(), token);
                    });

                UserDetailBox.Text = BuildCombinedOutput(result);
                if (IsSuccessCode(result.ExitCode))
                {
                    string suffix = systemAccountKnown ? string.Empty : " (warning: no matching Windows account)";
                    SetStatus("User " + username + " created (TOTP token, no prefix PIN)" + suffix + ".");
                    NewUsernameBox.Text = string.Empty;
                    await LoadUsersAsync();
                }
                else
                {
                    SetStatus("User creation failed. " + GetFriendlyExitText(result.ExitCode));
                }
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
        }

        private static bool IsDomainJoined()
        {
            try
            {
                using (System.DirectoryServices.DirectoryEntry rootDse = new System.DirectoryServices.DirectoryEntry("LDAP://rootDSE"))
                {
                    object defaultContext = rootDse.Properties["defaultNamingContext"].Value;
                    return defaultContext != null;
                }
            }
            catch (Exception)
            {
                return false;
            }
        }

        private async void UsersListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (refreshingUsers)
            {
                return;
            }

            UserSummary summary = UsersListBox.SelectedItem as UserSummary;
            if (summary == null)
            {
                ClearUserDetail();
                return;
            }

            await LoadUserDetailsAsync(summary);
        }

        private async void ActivateBtn_Click(object sender, RoutedEventArgs e)
        {
            await RunSelectedUserActionAsync("activate", delegate(string user, CancellationToken token)
            {
                return cliClient.ActivateUserAsync(user, GetTimeout(), token);
            });
        }

        private async void DeactivateBtn_Click(object sender, RoutedEventArgs e)
        {
            await RunSelectedUserActionAsync("deactivate", delegate(string user, CancellationToken token)
            {
                return cliClient.DeactivateUserAsync(user, GetTimeout(), token);
            });
        }

        private async void LockBtn_Click(object sender, RoutedEventArgs e)
        {
            await RunSelectedUserActionAsync("lock", delegate(string user, CancellationToken token)
            {
                return cliClient.LockUserAsync(user, GetTimeout(), token);
            });
        }

        private async void UnlockBtn_Click(object sender, RoutedEventArgs e)
        {
            await RunSelectedUserActionAsync("unlock", delegate(string user, CancellationToken token)
            {
                return cliClient.UnlockUserAsync(user, GetTimeout(), token);
            });
        }

        private async void ResyncBtn_Click(object sender, RoutedEventArgs e)
        {
            UserSummary summary = UsersListBox.SelectedItem as UserSummary;
            if (summary == null)
            {
                SetStatus("Select a user to resync.");
                return;
            }

            PromptDialog dialog = new PromptDialog(
                "Resync token",
                "Enter two consecutive OTP codes generated by the token of " + summary.Name +
                ". Both codes must be unused.",
                new[] { "FIRST OTP CODE", "SECOND OTP CODE" });
            dialog.Owner = this;
            if (dialog.ShowDialog() != true)
            {
                return;
            }

            string[] values = dialog.Values;
            if (values.Length < 2 || values[0].Length == 0 || values[1].Length == 0)
            {
                SetStatus("Two OTP codes are required for resynchronization.");
                return;
            }

            try
            {
                ProcessRunResult result = await RunOperationAsync(
                    "resync token",
                    delegate(CancellationToken token)
                    {
                        return cliClient.ResyncTokenAsync(summary.Name, values[0], values[1], GetTimeout(), token);
                    });

                UserDetailBox.Text = BuildCombinedOutput(result);
                if (IsSuccessCode(result.ExitCode))
                {
                    SetStatus("Token resynchronized for " + summary.Name + ".");
                    await LoadUserDetailsAsync(summary);
                }
                else
                {
                    SetStatus("Resynchronization failed. " + GetFriendlyExitText(result.ExitCode));
                }
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
        }

        private async void QrCodeBtn_Click(object sender, RoutedEventArgs e)
        {
            UserSummary summary = UsersListBox.SelectedItem as UserSummary;
            if (summary == null)
            {
                SetStatus("Select a user to show the provisioning QR code.");
                return;
            }

            // The PNG embeds the token secret; write it to a temp file and
            // delete it as soon as the pixels are loaded in memory.
            string tempFile = Path.Combine(Path.GetTempPath(), "multiotp_qrcode_" + Guid.NewGuid().ToString("N") + ".png");

            try
            {
                ProcessRunResult urlResult = await RunOperationAsync(
                    "read provisioning URL",
                    delegate(CancellationToken token)
                    {
                        return cliClient.GetUrlLinkAsync(summary.Name, GetTimeout(), token);
                    });

                string urlLink = (urlResult.StandardOutput ?? string.Empty).Trim();
                bool urlUsable = IsSuccessCode(urlResult.ExitCode) &&
                    (urlLink.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase) ||
                     urlLink.StartsWith("motp://", StringComparison.OrdinalIgnoreCase));

                if (!urlUsable)
                {
                    UserDetailBox.Text = BuildCombinedOutput(urlResult);
                    SetStatus("This token cannot be provisioned with a QR code. " + GetFriendlyExitText(urlResult.ExitCode));
                    return;
                }

                BitmapImage qrImage = null;
                ProcessRunResult qrResult = await RunOperationAsync(
                    "create QR code",
                    delegate(CancellationToken token)
                    {
                        return cliClient.CreateQrCodeAsync(summary.Name, tempFile, GetTimeout(), token);
                    });

                if (IsSuccessCode(qrResult.ExitCode) && File.Exists(tempFile))
                {
                    try
                    {
                        qrImage = LoadImageFile(tempFile);
                    }
                    catch (Exception)
                    {
                        qrImage = null;
                    }
                }

                string imageError = qrImage == null ? GetFriendlyExitText(qrResult.ExitCode) : null;
                QrCodeDialog dialog = new QrCodeDialog(summary.Name, qrImage, urlLink, imageError);
                dialog.Owner = this;
                dialog.ShowDialog();
                SetStatus("Provisioning information shown for " + summary.Name + ".");
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
            finally
            {
                TryDeleteFile(tempFile);
            }
        }

        private async void DisablePinBtn_Click(object sender, RoutedEventArgs e)
        {
            UserSummary summary = UsersListBox.SelectedItem as UserSummary;
            if (summary == null)
            {
                SetStatus("Select a user to disable the prefix PIN requirement.");
                return;
            }

            try
            {
                ProcessRunResult result = await RunOperationAsync(
                    "disable prefix PIN",
                    delegate(CancellationToken token)
                    {
                        return cliClient.SetUserAttributeAsync(summary.Name, "request_prefix_pin", "0", GetTimeout(), token);
                    });

                UserDetailBox.Text = BuildCombinedOutput(result);
                if (IsSuccessCode(result.ExitCode))
                {
                    SetStatus("Prefix PIN disabled for " + summary.Name + ". They can now verify with just the OTP.");
                    await LoadUserDetailsAsync(summary);
                }
                else
                {
                    SetStatus("Disable PIN failed. " + GetFriendlyExitText(result.ExitCode));
                }
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
        }

        private async void DeleteUserBtn_Click(object sender, RoutedEventArgs e)
        {
            UserSummary summary = UsersListBox.SelectedItem as UserSummary;
            if (summary == null)
            {
                SetStatus("Select a user to delete.");
                return;
            }

            if (!ConfirmAction(
                "Delete user " + summary.Name + "? This permanently removes the user and the associated token data.",
                "Delete user"))
            {
                return;
            }

            try
            {
                ProcessRunResult result = await RunOperationAsync(
                    "delete user",
                    delegate(CancellationToken token)
                    {
                        return cliClient.DeleteUserAsync(summary.Name, GetTimeout(), token);
                    });

                UserDetailBox.Text = BuildCombinedOutput(result);
                if (IsSuccessCode(result.ExitCode))
                {
                    SetStatus("User " + summary.Name + " deleted.");
                    ClearUserDetail();
                    await LoadUsersAsync();
                }
                else
                {
                    SetStatus("Delete failed. " + GetFriendlyExitText(result.ExitCode));
                }
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
        }

        private async Task LoadUsersAsync()
        {
            refreshingUsers = true;
            UsersListBox.SelectedItem = null;
            ClearUserDetail();

            try
            {
                ProcessRunResult result = await RunOperationAsync(
                    "load users",
                    delegate(CancellationToken token)
                    {
                        return cliClient.GetUsersAsync(GetTimeout(), token);
                    });

                if (!IsSuccessCode(result.ExitCode))
                {
                    UserDetailBox.Text = BuildCombinedOutput(result);
                    SetStatus("User list command failed. " + GetFriendlyExitText(result.ExitCode));
                    return;
                }

                List<UserSummary> users = result.StandardOutput
                    .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(delegate(string line) { return line.Trim(); })
                    .Where(delegate(string line) { return line.Length > 0; })
                    .Select(delegate(string user) { return new UserSummary { Name = user }; })
                    .ToList();

                UsersListBox.ItemsSource = users;

                if (users.Count == 0)
                {
                    UserDetailBox.Text = "No users were returned.";
                }

                SetStatus(users.Count.ToString() + " user(s) loaded.");
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
            finally
            {
                refreshingUsers = false;
            }
        }

        private async Task LoadUserDetailsAsync(UserSummary summary)
        {
            try
            {
                ProcessRunResult result = await RunOperationAsync(
                    "load user details",
                    delegate(CancellationToken token)
                    {
                        return cliClient.GetUserAsync(summary.Name, GetTimeout(), token);
                    });

                if (!IsSuccessCode(result.ExitCode))
                {
                    ClearUserDetail();
                    UserDetailBox.Text = BuildCombinedOutput(result);
                    SetStatus("User detail command failed. " + GetFriendlyExitText(result.ExitCode));
                    return;
                }

                UserDetail detail = UserDetail.Parse(result.StandardOutput);
                summary.TokenType = detail.TokenType;
                summary.Status = detail.Status;
                DetailUsernameText.Text = detail.Username;
                DetailTokenTypeText.Text = detail.TokenType;
                DetailStatusText.Text = detail.Status;
                DetailCreatedText.Text = detail.Created;
                DetailDigitsText.Text = detail.OtpDigits;
                DetailDescriptionText.Text = detail.Description;
                UserDetailBox.Text = detail.ToMaskedDisplayText();
                SetStatus("Details loaded for " + summary.Name + ".");
            }
            catch (Exception error)
            {
                ClearUserDetail();
                SetStatus(GetSafeExceptionMessage(error));
            }
        }

        private async Task RunSelectedUserActionAsync(
            string actionName,
            Func<string, CancellationToken, Task<ProcessRunResult>> action)
        {
            UserSummary summary = UsersListBox.SelectedItem as UserSummary;
            if (summary == null)
            {
                SetStatus("Select a user first.");
                return;
            }

            try
            {
                ProcessRunResult result = await RunOperationAsync(
                    actionName + " user",
                    delegate(CancellationToken token)
                    {
                        return action(summary.Name, token);
                    });

                UserDetailBox.Text = BuildCombinedOutput(result);
                if (IsSuccessCode(result.ExitCode))
                {
                    SetStatus("User " + summary.Name + ": " + actionName + " succeeded.");
                    await LoadUserDetailsAsync(summary);
                }
                else
                {
                    SetStatus(actionName + " failed. " + GetFriendlyExitText(result.ExitCode));
                }
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
        }

        // --- Tokens ---

        private async void RefreshTokensButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ProcessRunResult result = await RunOperationAsync(
                    "load tokens",
                    delegate(CancellationToken token)
                    {
                        return cliClient.GetTokensAsync(GetTimeout(), token);
                    });

                ShowOutputResult(TokensOutputBox, result, "Token list loaded.");
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
        }

        private async void AssignTokenBtn_Click(object sender, RoutedEventArgs e)
        {
            string username = TokenUsernameBox.Text.Trim();
            string tokenId = TokenIdBox.Text.Trim();

            try
            {
                ProcessRunResult result = await RunOperationAsync(
                    "assign token",
                    delegate(CancellationToken token)
                    {
                        return cliClient.AssignTokenAsync(username, tokenId, GetTimeout(), token);
                    });

                ShowOutputResult(TokensOutputBox, result, "Token " + tokenId + " assigned to " + username + ".");
            }
            catch (ArgumentException error)
            {
                SetStatus(error.Message);
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
        }

        private async void RemoveTokenBtn_Click(object sender, RoutedEventArgs e)
        {
            string username = TokenUsernameBox.Text.Trim();

            try
            {
                ProcessRunResult result = await RunOperationAsync(
                    "remove token",
                    delegate(CancellationToken token)
                    {
                        return cliClient.RemoveTokenAsync(username, GetTimeout(), token);
                    });

                ShowOutputResult(TokensOutputBox, result, "Token removed from " + username + ".");
            }
            catch (ArgumentException error)
            {
                SetStatus(error.Message);
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
        }

        private async void DeleteTokenBtn_Click(object sender, RoutedEventArgs e)
        {
            string tokenId = TokenIdBox.Text.Trim();
            if (tokenId.Length == 0)
            {
                SetStatus("Enter the token ID to delete.");
                TokenIdBox.Focus();
                return;
            }

            if (!ConfirmAction("Delete token " + tokenId + "? This cannot be undone.", "Delete token"))
            {
                return;
            }

            try
            {
                ProcessRunResult result = await RunOperationAsync(
                    "delete token",
                    delegate(CancellationToken token)
                    {
                        return cliClient.DeleteTokenAsync(tokenId, GetTimeout(), token);
                    });

                ShowOutputResult(TokensOutputBox, result, "Token " + tokenId + " deleted.");
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
        }

        // --- Logs ---

        private async void ShowLogBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ProcessRunResult result = await RunOperationAsync(
                    "read log",
                    delegate(CancellationToken token)
                    {
                        return cliClient.ShowLogAsync(GetTimeout(), token);
                    });

                ShowOutputResult(LogOutputBox, result, "Log loaded.");
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
        }

        private async void ClearLogBtn_Click(object sender, RoutedEventArgs e)
        {
            if (!ConfirmAction("Clear the multiOTP log?", "Clear log"))
            {
                return;
            }

            try
            {
                ProcessRunResult result = await RunOperationAsync(
                    "clear log",
                    delegate(CancellationToken token)
                    {
                        return cliClient.ClearLogAsync(GetTimeout(), token);
                    });

                ShowOutputResult(LogOutputBox, result, "Log cleared.");
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
        }

        private async void ErrorCodesBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ProcessRunResult result = await RunOperationAsync(
                    "read error codes",
                    delegate(CancellationToken token)
                    {
                        return cliClient.GetErrorCodesAsync(GetTimeout(), token);
                    });

                ShowOutputResult(LogOutputBox, result, "Error codes loaded.");
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
        }

        private async void VersionBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ProcessRunResult result = await RunOperationAsync(
                    "read version",
                    delegate(CancellationToken token)
                    {
                        return cliClient.GetVersionAsync(GetTimeout(), token);
                    });

                ShowOutputResult(LogOutputBox, result, "Version information loaded.");
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
        }

        // --- AD/LDAP ---

        private async void LdapCheckBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ProcessRunResult result = await RunOperationAsync(
                    "check LDAP connection",
                    delegate(CancellationToken token)
                    {
                        return cliClient.LdapCheckAsync(GetLdapTimeout(), token);
                    });

                ShowOutputResult(LdapOutputBox, result, "LDAP connection check finished.");
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
        }

        private async void LdapUsersListBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ProcessRunResult result = await RunOperationAsync(
                    "list LDAP users",
                    delegate(CancellationToken token)
                    {
                        return cliClient.LdapUsersListAsync(GetLdapTimeout(), token);
                    });

                ShowOutputResult(LdapOutputBox, result, "LDAP user list loaded.");
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
        }

        private async void LdapSyncBtn_Click(object sender, RoutedEventArgs e)
        {
            if (!ConfirmAction(
                "Synchronize AD/LDAP users into the multiOTP user store? Existing local users may be updated.",
                "LDAP synchronization"))
            {
                return;
            }

            try
            {
                ProcessRunResult result = await RunOperationAsync(
                    "synchronize LDAP users",
                    delegate(CancellationToken token)
                    {
                        return cliClient.LdapUsersSyncAsync(GetLdapTimeout(), token);
                    });

                ShowOutputResult(LdapOutputBox, result, "LDAP synchronization finished.");
                if (IsSuccessCode(result.ExitCode))
                {
                    await LoadUsersAsync();
                }
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
        }

        // --- Credential Provider settings ---

        private void SaveSettingsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                CredentialProviderSettings settings = new CredentialProviderSettings();
                settings.LogonMode = CombineScenario(LogonScopeBox, LogonExclusiveBox);
                settings.UnlockMode = CombineScenario(UnlockScopeBox, UnlockExclusiveBox);
                settings.TwoStepHideOtp = TwoStepHideOtpBox.IsChecked == true;

                registryService.Save(settings);
                LoadSettings();
                SetStatus("Credential Provider settings saved.");
            }
            catch (Exception error)
            {
                MessageBox.Show(
                    GetSafeExceptionMessage(error),
                    "Settings not saved",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                SetStatus("Settings were not saved.");
            }
        }

        // --- Maintenance ---

        private async void BackupBtn_Click(object sender, RoutedEventArgs e)
        {
            string password = BackupPasswordBox.Password;
            if (password.Length == 0)
            {
                SetStatus("Enter a backup password first.");
                BackupPasswordBox.Focus();
                return;
            }

            if (!ConfirmAction("Create an encrypted backup of the multiOTP configuration?", "Backup configuration"))
            {
                return;
            }

            try
            {
                ProcessRunResult result = await RunOperationAsync(
                    "backup configuration",
                    delegate(CancellationToken token)
                    {
                        return cliClient.BackupConfigAsync(password, GetTimeout(), token);
                    });

                ShowOutputResult(MaintenanceOutputBox, result, "Backup created.");
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
            finally
            {
                BackupPasswordBox.Password = string.Empty;
            }
        }

        private async void RestoreBtn_Click(object sender, RoutedEventArgs e)
        {
            string password = BackupPasswordBox.Password;
            if (password.Length == 0)
            {
                SetStatus("Enter the backup password to restore from.");
                BackupPasswordBox.Focus();
                return;
            }

            if (!ConfirmAction(
                "Restore the multiOTP configuration from the backup? Current configuration and users may be overwritten.",
                "Restore configuration"))
            {
                return;
            }

            try
            {
                ProcessRunResult result = await RunOperationAsync(
                    "restore configuration",
                    delegate(CancellationToken token)
                    {
                        return cliClient.RestoreConfigAsync(password, GetTimeout(), token);
                    });

                ShowOutputResult(MaintenanceOutputBox, result, "Configuration restored.");
                if (IsSuccessCode(result.ExitCode))
                {
                    await LoadUsersAsync();
                }
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
            finally
            {
                BackupPasswordBox.Password = string.Empty;
            }
        }

        private async void PurgeLockBtn_Click(object sender, RoutedEventArgs e)
        {
            if (!ConfirmAction("Purge the lock folder? Locked users and tokens become usable again.", "Purge locks"))
            {
                return;
            }

            try
            {
                ProcessRunResult result = await RunOperationAsync(
                    "purge lock folder",
                    delegate(CancellationToken token)
                    {
                        return cliClient.PurgeLockFolderAsync(GetTimeout(), token);
                    });

                ShowOutputResult(MaintenanceOutputBox, result, "Lock folder purged.");
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
        }

        private async void PurgeLdapCacheBtn_Click(object sender, RoutedEventArgs e)
        {
            if (!ConfirmAction("Purge the LDAP cache folder?", "Purge LDAP cache"))
            {
                return;
            }

            try
            {
                ProcessRunResult result = await RunOperationAsync(
                    "purge LDAP cache",
                    delegate(CancellationToken token)
                    {
                        return cliClient.PurgeLdapCacheAsync(GetTimeout(), token);
                    });

                ShowOutputResult(MaintenanceOutputBox, result, "LDAP cache purged.");
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
        }

        // --- Window / cancellation ---

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            CancellationTokenSource source = currentOperationCancellation;
            if (source != null)
            {
                source.Cancel();
                SetStatus("Canceling current operation...");
            }
        }

        private void Window_Closed(object sender, EventArgs e)
        {
            if (currentOperationCancellation != null)
            {
                currentOperationCancellation.Cancel();
            }
        }

        private async Task<ProcessRunResult> RunOperationAsync(
            string operationName,
            Func<CancellationToken, Task<ProcessRunResult>> operation)
        {
            CancellationTokenSource source = new CancellationTokenSource();
            currentOperationCancellation = source;

            try
            {
                SetBusy(true, operationName + "...");
                return await operation(source.Token);
            }
            finally
            {
                source.Dispose();
                currentOperationCancellation = null;
                SetBusy(false, "Ready");
            }
        }

        private void ShowVerifyResult(ProcessRunResult result)
        {
            string safeOutput = BuildCombinedOutput(result);
            VerifyOutputBox.Text = safeOutput;

            if (result.ExitCode == 0)
            {
                VerifyResultText.Foreground = FindResource("GoodColor") as Brush;
                VerifyResultText.Text = "Authentication accepted.";
                SetStatus("Authentication accepted.");
                return;
            }

            VerifyResultText.Foreground = FindResource("BadColor") as Brush;
            VerifyResultText.Text = "Authentication refused. " + GetFriendlyExitText(result.ExitCode);
            SetStatus("Authentication refused. Exit code: " + result.ExitCode);
        }

        private void ShowVerifyFailure(string message)
        {
            VerifyResultText.Foreground = FindResource("BadColor") as Brush;
            VerifyResultText.Text = message;
            SetStatus(message);
        }

        private void ShowOutputResult(TextBox target, ProcessRunResult result, string successStatus)
        {
            target.Text = BuildCombinedOutput(result);
            if (IsSuccessCode(result.ExitCode))
            {
                SetStatus(successStatus);
            }
            else
            {
                SetStatus("Command failed. " + GetFriendlyExitText(result.ExitCode));
            }
        }

        private void ClearUserDetail()
        {
            DetailUsernameText.Text = "-";
            DetailTokenTypeText.Text = "-";
            DetailStatusText.Text = "-";
            DetailCreatedText.Text = "-";
            DetailDigitsText.Text = "-";
            DetailDescriptionText.Text = "-";
            UserDetailBox.Text = string.Empty;
        }

        private void LoadSettings()
        {
            CredentialProviderSettings settings = registryService.Load();
            string logonMode = settings.LogonMode ?? "3d";
            string unlockMode = settings.UnlockMode ?? "3d";

            LogonScopeBox.SelectedValue = logonMode.Substring(0, 1);
            UnlockScopeBox.SelectedValue = unlockMode.Substring(0, 1);
            LogonExclusiveBox.SelectedValue = logonMode.Length > 1 ? logonMode.Substring(1) : "d";
            UnlockExclusiveBox.SelectedValue = unlockMode.Length > 1 ? unlockMode.Substring(1) : "d";
            TwoStepHideOtpBox.IsChecked = settings.TwoStepHideOtp;
        }

        private string CombineScenario(ComboBox scopeBox, ComboBox providerBox)
        {
            string scope = Convert.ToString(scopeBox.SelectedValue);
            string provider = Convert.ToString(providerBox.SelectedValue);

            if (string.IsNullOrEmpty(scope))
            {
                scope = "0";
            }

            if (string.IsNullOrEmpty(provider))
            {
                provider = "d";
            }

            return scope + provider;
        }

        private bool ConfirmAction(string message, string title)
        {
            return MessageBox.Show(
                message,
                title,
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No) == MessageBoxResult.Yes;
        }

        private TimeSpan GetTimeout()
        {
            int seconds;
            if (!int.TryParse(TimeoutBox.Text.Trim(), out seconds))
            {
                seconds = 5;
            }

            if (seconds < 1)
            {
                seconds = 1;
            }
            else if (seconds > 300)
            {
                seconds = 300;
            }

            return TimeSpan.FromSeconds(seconds);
        }

        // Directory queries over LDAP can be slow; never use a timeout shorter than 30s.
        private TimeSpan GetLdapTimeout()
        {
            TimeSpan configured = GetTimeout();
            TimeSpan minimum = TimeSpan.FromSeconds(30);
            return configured > minimum ? configured : minimum;
        }

        private void SetBusy(bool busy, string status)
        {
            if (actionButtons != null)
            {
                foreach (Button button in actionButtons)
                {
                    button.IsEnabled = !busy;
                }
            }

            UsersListBox.IsEnabled = !busy;
            CancelButton.IsEnabled = busy;
            SetStatus(status);
        }

        private void SetStatus(string status)
        {
            StatusText.Text = status;
        }

        private static BitmapImage LoadImageFile(string path)
        {
            // Load with OnLoad so the file handle is released immediately.
            BitmapImage image = new BitmapImage();
            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                image.BeginInit();
                image.CacheOption = BitmapCacheOption.OnLoad;
                image.StreamSource = stream;
                image.EndInit();
            }
            image.Freeze();
            return image;
        }

        private static void TryDeleteFile(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        private static bool IsSuccessCode(int exitCode)
        {
            // multiOTP returns 0 for OK and 11-19 for successful INFO operations.
            return exitCode == 0 || (exitCode >= 11 && exitCode <= 19);
        }

        private static string BuildCombinedOutput(ProcessRunResult result)
        {
            List<string> sections = new List<string>();
            sections.Add("Exit code: " + result.ExitCode);

            if (!string.IsNullOrWhiteSpace(result.StandardOutput))
            {
                sections.Add("Standard output:");
                sections.Add(MaskSensitiveText(result.StandardOutput.Trim()));
            }

            if (!string.IsNullOrWhiteSpace(result.StandardError))
            {
                sections.Add("Standard error:");
                sections.Add(MaskSensitiveText(result.StandardError.Trim()));
            }

            return string.Join(Environment.NewLine + Environment.NewLine, sections.ToArray());
        }

        private static string MaskSensitiveText(string text)
        {
            string[] lines = text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            for (int index = 0; index < lines.Length; index++)
            {
                string line = lines[index];
                string lowerCaseLine = line.ToLowerInvariant();
                bool hasSensitiveKey = lowerCaseLine.Contains("seed") ||
                                       lowerCaseLine.Contains("secret") ||
                                       lowerCaseLine.Contains("password") ||
                                       lowerCaseLine.Contains("pin");

                if (hasSensitiveKey)
                {
                    int separatorIndex = line.IndexOf(':');
                    if (separatorIndex >= 0)
                    {
                        lines[index] = line.Substring(0, separatorIndex + 1) + " ********";
                    }
                    else
                    {
                        lines[index] = "********";
                    }
                }
            }

            return string.Join(Environment.NewLine, lines);
        }

        private static string GetFriendlyExitText(int exitCode)
        {
            switch (exitCode)
            {
                case 0:
                    return "OK.";
                case 11:
                    return "User successfully created or updated.";
                case 12:
                    return "User successfully deleted.";
                case 13:
                    return "User PIN code successfully changed.";
                case 14:
                    return "Token resynchronized successfully.";
                case 15:
                    return "Token definition file imported.";
                case 16:
                    return "QR code created.";
                case 17:
                    return "Provisioning URL created.";
                case 18:
                    return "Static code request received.";
                case 19:
                    return "Operation completed.";
                case 20:
                    return "The user is blacklisted.";
                case 21:
                    return "The user does not exist.";
                case 22:
                    return "The user already exists.";
                case 23:
                    return "The token algorithm is invalid.";
                case 24:
                    return "The user or token is locked (too many tries).";
                case 25:
                    return "The user is delayed (too many tries).";
                case 26:
                    return "The token was already used.";
                case 27:
                    return "Token resynchronization failed.";
                case 28:
                    return "Unable to write the changes.";
                case 29:
                    return "The token does not exist.";
                case 30:
                    return "A required parameter is missing.";
                case 31:
                    return "The token definition file does not exist.";
                case 32:
                    return "The token definition file was not imported.";
                case 33:
                    return "Encryption key mismatch.";
                case 34:
                    return "The linked user does not exist.";
                case 35:
                    return "The user was not created.";
                case 36:
                    return "The token does not exist.";
                case 37:
                    return "The token is already assigned.";
                case 38:
                    return "The user is disabled.";
                case 39:
                    return "The operation was aborted.";
                case 40:
                    return "SQL query error.";
                case 41:
                    return "SQL error.";
                case 42:
                    return "The key is not in the table schema.";
                case 43:
                    return "The SQL entry cannot be updated.";
                case 58:
                    return "A file is missing.";
                case 59:
                    return "The restore password is incorrect.";
                case 60:
                    return "No information on where to send the SMS code.";
                case 61:
                    return "An error occurred while sending the SMS code.";
                case 62:
                    return "The SMS provider is not supported.";
                case 63:
                    return "The SMS code has expired.";
                case 64:
                    return "The SMS code cannot be resent right now.";
                case 65:
                    return "The SMS code request is not allowed.";
                case 66:
                    return "The email code request is not allowed.";
                case 67:
                    return "No information on where to send the email code.";
                case 68:
                    return "An error occurred while sending the email code.";
                case 69:
                    return "Failed to send the email.";
                case 70:
                    return "Server authentication error.";
                case 71:
                    return "Server request is not correctly formatted.";
                case 72:
                    return "Server answer is not correctly formatted.";
                case 73:
                    return "Email SMTP server is not defined.";
                case 79:
                    return "AD/LDAP connection error.";
                case 80:
                    return "Server cache error.";
                case 81:
                    return "Cache too old for this user, account autolocked.";
                case 82:
                    return "User is not allowed for this device.";
                case 88:
                    return "Device is not defined as a HA slave.";
                case 89:
                    return "Device is not defined as a HA master.";
                case 90:
                    return "AD/LDAP authentication failed.";
                case 91:
                    return "Authentication failed (without2FA token not authorized here).";
                case 92:
                    return "Authentication failed (bad password).";
                case 93:
                    return "Authentication failed (time based token probably out of sync).";
                case 94:
                    return "API request error.";
                case 95:
                    return "API authentication failed.";
                case 96:
                    return "Push authentication timeout.";
                case 97:
                    return "Push authentication denied.";
                case 98:
                    return "Authentication failed (wrong token length).";
                case 99:
                    return "Authentication failed (unknown error).";
                default:
                    return "Exit code " + exitCode + ".";
            }
        }

        private static string GetSafeExceptionMessage(Exception exception)
        {
            if (exception is TimeoutException)
            {
                return "The operation timed out.";
            }

            if (exception is OperationCanceledException)
            {
                return "The operation was canceled.";
            }

            if (exception is ArgumentException)
            {
                return exception.Message;
            }

            if (exception is System.IO.FileNotFoundException)
            {
                return "multiotp.exe was not found next to MultiOtpManager.exe.";
            }

            return "The operation failed. " + exception.GetType().Name + ".";
        }

        // Small modal dialog built in code (no XAML dependency) to collect one or
        // more labeled values. Used for token resynchronization.
        private sealed class PromptDialog : Window
        {
            private readonly List<TextBox> boxes = new List<TextBox>();

            public PromptDialog(string title, string description, string[] fieldLabels)
            {
                Title = title;
                Width = 380;
                SizeToContent = SizeToContent.Height;
                WindowStartupLocation = WindowStartupLocation.CenterOwner;
                ResizeMode = ResizeMode.NoResize;
                ShowInTaskbar = false;
                Background = new SolidColorBrush(Color.FromRgb(0xF3, 0xF5, 0xF7));

                StackPanel root = new StackPanel();
                root.Margin = new Thickness(16);

                if (!string.IsNullOrEmpty(description))
                {
                    TextBlock descriptionText = new TextBlock();
                    descriptionText.Text = description;
                    descriptionText.TextWrapping = TextWrapping.Wrap;
                    descriptionText.Foreground = new SolidColorBrush(Color.FromRgb(0x22, 0x30, 0x38));
                    descriptionText.Margin = new Thickness(0, 0, 0, 12);
                    root.Children.Add(descriptionText);
                }

                foreach (string label in fieldLabels)
                {
                    TextBlock caption = new TextBlock();
                    caption.Text = label;
                    caption.FontSize = 11;
                    caption.Foreground = new SolidColorBrush(Color.FromRgb(0x61, 0x70, 0x7B));
                    caption.Margin = new Thickness(0, 0, 0, 3);
                    root.Children.Add(caption);

                    TextBox box = new TextBox();
                    box.Height = 28;
                    box.VerticalContentAlignment = VerticalAlignment.Center;
                    boxes.Add(box);

                    Border wrapper = new Border();
                    wrapper.Child = box;
                    wrapper.Background = new SolidColorBrush(Colors.White);
                    wrapper.BorderBrush = new SolidColorBrush(Color.FromRgb(0xB8, 0xC0, 0xC8));
                    wrapper.BorderThickness = new Thickness(1);
                    wrapper.Margin = new Thickness(0, 0, 0, 10);
                    root.Children.Add(wrapper);
                }

                StackPanel buttons = new StackPanel();
                buttons.Orientation = Orientation.Horizontal;
                buttons.HorizontalAlignment = HorizontalAlignment.Right;
                buttons.Margin = new Thickness(0, 6, 0, 0);

                Button okButton = new Button();
                okButton.Content = "OK";
                okButton.IsDefault = true;
                okButton.MinWidth = 88;
                okButton.Height = 30;
                okButton.Margin = new Thickness(0, 0, 6, 0);
                okButton.Click += delegate { DialogResult = true; };

                Button cancelButton = new Button();
                cancelButton.Content = "Cancel";
                cancelButton.IsCancel = true;
                cancelButton.MinWidth = 88;
                cancelButton.Height = 30;

                buttons.Children.Add(okButton);
                buttons.Children.Add(cancelButton);
                root.Children.Add(buttons);

                Content = root;
                Loaded += delegate
                {
                    if (boxes.Count > 0)
                    {
                        boxes[0].Focus();
                    }
                };
            }

            public string[] Values
            {
                get
                {
                    string[] values = new string[boxes.Count];
                    for (int index = 0; index < boxes.Count; index++)
                    {
                        values[index] = boxes[index].Text.Trim();
                    }
                    return values;
                }
            }
        }

        // Modal dialog showing the provisioning QR code and the otpauth URL.
        private sealed class QrCodeDialog : Window
        {
            public QrCodeDialog(string username, BitmapImage qrImage, string urlLink, string imageError)
            {
                Title = "Provisioning - " + username;
                Width = 460;
                SizeToContent = SizeToContent.Height;
                WindowStartupLocation = WindowStartupLocation.CenterOwner;
                ResizeMode = ResizeMode.NoResize;
                ShowInTaskbar = false;
                Background = new SolidColorBrush(Color.FromRgb(0xF3, 0xF5, 0xF7));

                StackPanel root = new StackPanel();
                root.Margin = new Thickness(16);

                TextBlock hint = new TextBlock();
                hint.Text = "Scan the code with Google Authenticator, FreeOTP or any compatible authenticator app. The code contains the token secret: do not share it.";
                hint.TextWrapping = TextWrapping.Wrap;
                hint.Foreground = new SolidColorBrush(Color.FromRgb(0x22, 0x30, 0x38));
                hint.Margin = new Thickness(0, 0, 0, 12);
                root.Children.Add(hint);

                if (qrImage != null)
                {
                    Image image = new Image();
                    image.Source = qrImage;
                    image.Width = 260;
                    image.Height = 260;
                    image.Stretch = Stretch.Uniform;
                    image.HorizontalAlignment = HorizontalAlignment.Center;

                    Border frame = new Border();
                    frame.Background = new SolidColorBrush(Colors.White);
                    frame.BorderBrush = new SolidColorBrush(Color.FromRgb(0xD5, 0xDB, 0xE1));
                    frame.BorderThickness = new Thickness(1);
                    frame.Padding = new Thickness(12);
                    frame.HorizontalAlignment = HorizontalAlignment.Center;
                    frame.Margin = new Thickness(0, 0, 0, 12);
                    frame.Child = image;
                    root.Children.Add(frame);
                }
                else
                {
                    TextBlock imageNote = new TextBlock();
                    imageNote.Text = "The QR image could not be generated (" + imageError + "). Use the provisioning URL below instead.";
                    imageNote.TextWrapping = TextWrapping.Wrap;
                    imageNote.Foreground = new SolidColorBrush(Color.FromRgb(0xA3, 0x31, 0x31));
                    imageNote.Margin = new Thickness(0, 0, 0, 12);
                    root.Children.Add(imageNote);
                }

                TextBlock urlCaption = new TextBlock();
                urlCaption.Text = "PROVISIONING URL";
                urlCaption.FontSize = 11;
                urlCaption.Foreground = new SolidColorBrush(Color.FromRgb(0x61, 0x70, 0x7B));
                urlCaption.Margin = new Thickness(0, 0, 0, 3);
                root.Children.Add(urlCaption);

                TextBox urlBox = new TextBox();
                urlBox.IsReadOnly = true;
                urlBox.Text = urlLink;
                urlBox.TextWrapping = TextWrapping.Wrap;
                urlBox.Height = 56;
                urlBox.VerticalScrollBarVisibility = ScrollBarVisibility.Auto;
                urlBox.Margin = new Thickness(0, 0, 0, 10);
                root.Children.Add(urlBox);

                StackPanel buttons = new StackPanel();
                buttons.Orientation = Orientation.Horizontal;
                buttons.HorizontalAlignment = HorizontalAlignment.Right;
                buttons.Margin = new Thickness(0, 6, 0, 0);

                Button copyButton = new Button();
                copyButton.Content = "Copy URL";
                copyButton.MinWidth = 88;
                copyButton.Height = 30;
                copyButton.Margin = new Thickness(0, 0, 6, 0);
                copyButton.Click += delegate
                {
                    try
                    {
                        Clipboard.SetText(urlLink);
                        copyButton.Content = "Copied";
                    }
                    catch (Exception)
                    {
                        copyButton.Content = "Copy failed";
                    }
                };

                Button closeButton = new Button();
                closeButton.Content = "Close";
                closeButton.IsCancel = true;
                closeButton.MinWidth = 88;
                closeButton.Height = 30;

                buttons.Children.Add(copyButton);
                buttons.Children.Add(closeButton);
                root.Children.Add(buttons);

                Content = root;
            }
        }
    }
}
