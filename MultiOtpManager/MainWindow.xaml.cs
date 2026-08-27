using MultiOtpManager.Core;
using MultiOtpManager.Properties;
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
using MultiOtpManager.Core;

namespace MultiOtpManager
{
    public partial class MainWindow
    {
        private readonly MultiOtpCliClient cliClient;
        private readonly CredentialProviderRegistryService registryService;
        private readonly SystemUserProbe systemUserProbe;
        private AppSettings appSettings;
        private bool suppressLanguageChangeHandler;
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
            appSettings = AppSettings.Load();
            InitializeLanguageComboBox();
            LoadSettings();
        }

        private void InitializeLanguageComboBox()
        {
            // Match the ComboBox selection to the saved language without
            // triggering SelectionChanged (which would prompt to restart).
            suppressLanguageChangeHandler = true;
            try
            {
                string saved = appSettings.Language ?? string.Empty;
                foreach (object rawItem in LanguageComboBox.Items)
                {
                    ComboBoxItem candidate = rawItem as ComboBoxItem;
                    if (candidate != null && string.Equals((string)candidate.Tag, saved, StringComparison.OrdinalIgnoreCase))
                    {
                        LanguageComboBox.SelectedItem = candidate;
                        return;
                    }
                }
                if (LanguageComboBox.Items.Count > 0)
                {
                    LanguageComboBox.SelectedIndex = 0;
                }
            }
            finally
            {
                suppressLanguageChangeHandler = false;
            }
        }

        private void LanguageComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (suppressLanguageChangeHandler || appSettings == null)
            {
                return;
            }

            ComboBoxItem item = LanguageComboBox.SelectedItem as ComboBoxItem;
            if (item == null)
            {
                return;
            }

            string newLanguage = (item.Tag as string) ?? string.Empty;
            string currentLanguage = appSettings.Language ?? string.Empty;
            if (string.Equals(newLanguage, currentLanguage, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            appSettings.Language = newLanguage;
            appSettings.Save();

            MessageBoxResult result = MessageBox.Show(
                string.IsNullOrEmpty(newLanguage)
                    ? Resources.Message_LanguageChangedToSystemDefault
                    : Resources.Message_LanguageRestartRequired,
                Resources.Dialog_LanguageChangeTitle,
                MessageBoxButton.YesNo,
                MessageBoxImage.Information);

            if (result == MessageBoxResult.Yes)
            {
                RestartApplication();
            }
        }

        private static void RestartApplication()
        {
            try
            {
                string exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = exePath,
                    UseShellExecute = true,
                });
            }
            catch (Exception)
            {
                return;
            }

            Application.Current.Shutdown();
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

        private async void MainTabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // Auto-refresh the Users list every time the tab becomes active so the
            // operator sees a fresh view without having to click Refresh first.
            if (!ReferenceEquals(MainTabs.SelectedItem, UsersTab) || refreshingUsers)
            {
                return;
            }

            await LoadUsersAsync();
        }

        private async void CreateUserButton_Click(object sender, RoutedEventArgs e)
        {
            string username = NewUsernameBox.Text.Trim();
            if (username.Length == 0)
            {
                SetStatus(Resources.Message_EnterUsername);
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
                    string.Format(
                        Resources.Dialog_UserNotFoundMessage,
                        username,
                        IsDomainJoined() ? " or in the joined domain" : string.Empty),
                    Resources.Dialog_UserNotFoundTitle))
                {
                    SetStatus(string.Format(Resources.Message_UserCreationCanceled, username));
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
                    SetStatus(string.Format(Resources.Message_UserCreated, username, suffix));
                    NewUsernameBox.Text = string.Empty;
                    await LoadUsersAsync();
                }
                else
                {
                    SetStatus(Resources.Message_UserCreationFailed + " " + GetFriendlyExitText(result.ExitCode));
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
                SetStatus(Resources.Message_SelectUserToResync);
                return;
            }

            PromptDialog dialog = new PromptDialog(
                Resources.Dialog_ResyncTokenTitle,
                string.Format(Resources.Dialog_ResyncTokenMessage, summary.Name),
                new[] { Resources.Prompt_FirstOtpCode, Resources.Prompt_SecondOtpCode });
            dialog.Owner = this;
            if (dialog.ShowDialog() != true)
            {
                return;
            }

            string[] values = dialog.Values;
            if (values.Length < 2 || values[0].Length == 0 || values[1].Length == 0)
            {
                SetStatus(Resources.Message_TwoOtpCodesRequired);
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
                    SetStatus(string.Format(Resources.Message_TokenResynchronized, summary.Name));
                    await LoadUserDetailsAsync(summary);
                }
                else
                {
                    SetStatus(Resources.Message_ResyncFailed + " " + GetFriendlyExitText(result.ExitCode));
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
                SetStatus(Resources.Message_SelectUserForQrCode);
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
                    SetStatus(Resources.Message_TokenNoQrCode + " " + GetFriendlyExitText(urlResult.ExitCode));
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
                SetStatus(string.Format(Resources.Message_QrCodeShown, summary.Name));
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
                SetStatus(Resources.Message_SelectUserToDisablePin);
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
                    SetStatus(string.Format(Resources.Message_PrefixPinDisabled, summary.Name));
                    await LoadUserDetailsAsync(summary);
                }
                else
                {
                    SetStatus(Resources.Message_DisablePinFailed + " " + GetFriendlyExitText(result.ExitCode));
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
                SetStatus(Resources.Message_SelectUserToDelete);
                return;
            }

            if (!ConfirmAction(
                string.Format(Resources.Dialog_DeleteUserMessage, summary.Name),
                Resources.Dialog_DeleteUserTitle))
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
                    SetStatus(string.Format(Resources.Message_UserDeleted, summary.Name));
                    ClearUserDetail();
                    await LoadUsersAsync();
                }
                else
                {
                    SetStatus(Resources.Message_DeleteFailed + " " + GetFriendlyExitText(result.ExitCode));
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
                    SetStatus(Resources.Message_UserListFailed + " " + GetFriendlyExitText(result.ExitCode));
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
                    UserDetailBox.Text = Resources.Message_NoUsersReturned;
                }

                SetStatus(string.Format(Resources.Message_UsersLoaded, users.Count));
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
                    SetStatus(Resources.Message_UserDetailFailed + " " + GetFriendlyExitText(result.ExitCode));
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
                SetStatus(string.Format(Resources.Message_DetailsLoaded, summary.Name));
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
                SetStatus(Resources.Message_SelectUserFirst);
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
                    SetStatus(string.Format(Resources.Message_UserActionSucceeded, summary.Name, actionName));
                    await LoadUserDetailsAsync(summary);
                }
                else
                {
                    SetStatus(string.Format(Resources.Message_UserActionFailed, actionName, GetFriendlyExitText(result.ExitCode)));
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

                if (!IsSuccessCode(result.ExitCode))
                {
                    TokensListBox.ItemsSource = null;
                    ShowOutputResult(TokensOutputBox, result, Resources.Message_TokenListLoaded);
                    return;
                }

                List<string> tokens = result.StandardOutput
                    .Split(new[] { '\r', '\n', '\t' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(delegate(string line) { return line.Trim(); })
                    .Where(delegate(string line) { return line.Length > 0; })
                    .ToList();

                TokensListBox.ItemsSource = tokens;
                TokensOutputBox.Clear();

                if (tokens.Count == 0)
                {
                    SetStatus(Resources.Message_NoTokensReturned);
                }
                else
                {
                    SetStatus(string.Format(Resources.Message_TokensLoaded, tokens.Count));
                }
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

                ShowOutputResult(TokensOutputBox, result, string.Format(Resources.Message_TokenAssigned, tokenId, username));
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

                ShowOutputResult(TokensOutputBox, result, string.Format(Resources.Message_TokenRemoved, username));
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
                SetStatus(Resources.Message_EnterTokenIdToDelete);
                TokenIdBox.Focus();
                return;
            }

            if (!ConfirmAction(string.Format(Resources.Dialog_DeleteTokenMessage, tokenId), Resources.Dialog_DeleteTokenTitle))
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

                ShowOutputResult(TokensOutputBox, result, string.Format(Resources.Message_TokenDeleted, tokenId));

                // Drop the deleted token from the visible list so the UI does not
                // keep showing data that is no longer in the backend.
                if (IsSuccessCode(result.ExitCode))
                {
                    List<string> current = TokensListBox.ItemsSource as List<string>;
                    if (current != null)
                    {
                        TokensListBox.ItemsSource = current.Where(delegate(string token) { return token != tokenId; }).ToList();
                    }
                }
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

                ShowOutputResult(LogOutputBox, result, Resources.Message_LogLoaded);
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
        }

        private async void ClearLogBtn_Click(object sender, RoutedEventArgs e)
        {
            if (!ConfirmAction(Resources.Dialog_ClearLogMessage, Resources.Dialog_ClearLogTitle))
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

                ShowOutputResult(LogOutputBox, result, Resources.Message_LogCleared);
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

                ShowOutputResult(LogOutputBox, result, Resources.Message_ErrorCodesLoaded);
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

                ShowOutputResult(LogOutputBox, result, Resources.Message_VersionLoaded);
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

                ShowOutputResult(LdapOutputBox, result, Resources.Message_LdapCheckFinished);
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

                ShowOutputResult(LdapOutputBox, result, Resources.Message_LdapUserListLoaded);
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
        }

        private async void LdapSyncBtn_Click(object sender, RoutedEventArgs e)
        {
            if (!ConfirmAction(
                Resources.Dialog_LdapSyncMessage,
                Resources.Dialog_LdapSyncTitle))
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

                ShowOutputResult(LdapOutputBox, result, Resources.Message_LdapSyncFinished);
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
                SetStatus(Resources.Message_SettingsSaved);
            }
            catch (Exception error)
            {
                MessageBox.Show(
                    GetSafeExceptionMessage(error),
                    Resources.Dialog_SettingsNotSavedTitle,
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                SetStatus(Resources.Message_SettingsNotSaved);
            }
        }

        // --- Maintenance ---

        private async void BackupBtn_Click(object sender, RoutedEventArgs e)
        {
            string password = BackupPasswordBox.Password;
            if (password.Length == 0)
            {
                SetStatus(Resources.Message_EnterBackupPassword);
                BackupPasswordBox.Focus();
                return;
            }

            if (!ConfirmAction(Resources.Dialog_BackupMessage, Resources.Dialog_BackupTitle))
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

                ShowOutputResult(MaintenanceOutputBox, result, Resources.Message_BackupCreated);
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
                SetStatus(Resources.Message_EnterRestorePassword);
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

                ShowOutputResult(MaintenanceOutputBox, result, Resources.Message_ConfigurationRestored);
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
            if (!ConfirmAction(Resources.Dialog_PurgeLocksMessage, Resources.Dialog_PurgeLocksTitle))
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

                ShowOutputResult(MaintenanceOutputBox, result, Resources.Message_LockFolderPurged);
            }
            catch (Exception error)
            {
                SetStatus(GetSafeExceptionMessage(error));
            }
        }

        private async void PurgeLdapCacheBtn_Click(object sender, RoutedEventArgs e)
        {
            if (!ConfirmAction(Resources.Dialog_PurgeLdapCacheMessage, Resources.Dialog_PurgeLdapCacheTitle))
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

                ShowOutputResult(MaintenanceOutputBox, result, Resources.Message_LdapCachePurged);
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
                SetStatus(Resources.Status_CancelingOperation);
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
                SetBusy(true, string.Format(Resources.Status_OperationInProgress, operationName));
                return await operation(source.Token);
            }
            finally
            {
                source.Dispose();
                currentOperationCancellation = null;
                SetBusy(false, Resources.Status_Ready);
            }
        }

        private void ShowVerifyResult(ProcessRunResult result)
        {
            string safeOutput = BuildCombinedOutput(result);
            VerifyOutputBox.Text = safeOutput;

            if (result.ExitCode == 0)
            {
                VerifyResultText.Foreground = FindResource("GoodColor") as Brush;
                VerifyResultText.Text = Resources.Message_AuthenticationAccepted;
                SetStatus(Resources.Message_AuthenticationAccepted);
                return;
            }

            VerifyResultText.Foreground = FindResource("BadColor") as Brush;
            VerifyResultText.Text = string.Format(Resources.Message_AuthenticationRefused, GetFriendlyExitText(result.ExitCode));
            SetStatus(string.Format(Resources.Message_AuthenticationRefusedExitCode, result.ExitCode));
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
                SetStatus(string.Format(Resources.Message_CommandFailed, GetFriendlyExitText(result.ExitCode)));
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

            // On success, lead with the friendly description. On failure, keep the
            // raw exit code visible so it stays easy to match against multiOTP docs.
            if (IsSuccessCode(result.ExitCode))
            {
                sections.Add(GetFriendlyExitText(result.ExitCode));
            }
            else
            {
                sections.Add(string.Format(Resources.Output_ExitCodeWithMessage, result.ExitCode, GetFriendlyExitText(result.ExitCode)));
            }

            if (!string.IsNullOrWhiteSpace(result.StandardOutput))
            {
                sections.Add(Resources.Output_StandardOutputHeader);
                sections.Add(MaskSensitiveText(result.StandardOutput.Trim()));
            }

            if (!string.IsNullOrWhiteSpace(result.StandardError))
            {
                sections.Add(Resources.Output_StandardErrorHeader);
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
                    return Resources.Code_0;
                case 11:
                    return Resources.Code_11;
                case 12:
                    return Resources.Code_12;
                case 13:
                    return Resources.Code_13;
                case 14:
                    return Resources.Code_14;
                case 15:
                    return Resources.Code_15;
                case 16:
                    return Resources.Code_16;
                case 17:
                    return Resources.Code_17;
                case 18:
                    return Resources.Code_18;
                case 19:
                    return Resources.Code_19;
                case 20:
                    return Resources.Code_20;
                case 21:
                    return Resources.Code_21;
                case 22:
                    return Resources.Code_22;
                case 23:
                    return Resources.Code_23;
                case 24:
                    return Resources.Code_24;
                case 25:
                    return Resources.Code_25;
                case 26:
                    return Resources.Code_26;
                case 27:
                    return Resources.Code_27;
                case 28:
                    return Resources.Code_28;
                case 29:
                    return Resources.Code_29;
                case 30:
                    return Resources.Code_30;
                case 31:
                    return Resources.Code_31;
                case 32:
                    return Resources.Code_32;
                case 33:
                    return Resources.Code_33;
                case 34:
                    return Resources.Code_34;
                case 35:
                    return Resources.Code_35;
                case 36:
                    return Resources.Code_29;
                case 37:
                    return Resources.Code_37;
                case 38:
                    return Resources.Code_38;
                case 39:
                    return Resources.Code_39;
                case 40:
                    return Resources.Code_40;
                case 41:
                    return Resources.Code_41;
                case 42:
                    return Resources.Code_42;
                case 43:
                    return Resources.Code_43;
                case 58:
                    return Resources.Code_58;
                case 59:
                    return Resources.Code_59;
                case 60:
                    return Resources.Code_60;
                case 61:
                    return Resources.Code_61;
                case 62:
                    return Resources.Code_62;
                case 63:
                    return Resources.Code_63;
                case 64:
                    return Resources.Code_64;
                case 65:
                    return Resources.Code_65;
                case 66:
                    return Resources.Code_66;
                case 67:
                    return Resources.Code_67;
                case 68:
                    return Resources.Code_68;
                case 69:
                    return Resources.Code_69;
                case 70:
                    return Resources.Code_70;
                case 71:
                    return Resources.Code_71;
                case 72:
                    return Resources.Code_72;
                case 73:
                    return Resources.Code_73;
                case 79:
                    return Resources.Code_79;
                case 80:
                    return Resources.Code_80;
                case 81:
                    return Resources.Code_81;
                case 82:
                    return Resources.Code_82;
                case 88:
                    return Resources.Code_88;
                case 89:
                    return Resources.Code_89;
                case 90:
                    return Resources.Code_90;
                case 91:
                    return Resources.Code_91;
                case 92:
                    return Resources.Code_92;
                case 93:
                    return Resources.Code_93;
                case 94:
                    return Resources.Code_94;
                case 95:
                    return Resources.Code_95;
                case 96:
                    return Resources.Code_96;
                case 97:
                    return Resources.Code_97;
                case 98:
                    return Resources.Code_98;
                case 99:
                    return Resources.Code_99;
                default:
                    return string.Format(Resources.Code_Unknown, exitCode);
            }
        }

        private static string GetSafeExceptionMessage(Exception exception)
        {
            if (exception is TimeoutException)
            {
                return Resources.Message_OperationTimedOut;
            }

            if (exception is OperationCanceledException)
            {
                return Resources.Message_OperationCanceled;
            }

            if (exception is ArgumentException)
            {
                return exception.Message;
            }

            if (exception is System.IO.FileNotFoundException)
            {
                return Resources.Message_MultiotpNotFound;
            }

            return string.Format(Resources.Message_OperationFailedWithType, exception.GetType().Name);
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
                okButton.Content = Resources.Prompt_Ok;
                okButton.IsDefault = true;
                okButton.MinWidth = 88;
                okButton.Height = 30;
                okButton.Margin = new Thickness(0, 0, 6, 0);
                okButton.Click += delegate { DialogResult = true; };

                Button cancelButton = new Button();
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
                Title = string.Format(Resources.Dialog_QrCodeTitle, username);
                Width = 460;
                SizeToContent = SizeToContent.Height;
                WindowStartupLocation = WindowStartupLocation.CenterOwner;
                ResizeMode = ResizeMode.NoResize;
                ShowInTaskbar = false;
                Background = new SolidColorBrush(Color.FromRgb(0xF3, 0xF5, 0xF7));

                StackPanel root = new StackPanel();
                root.Margin = new Thickness(16);

                TextBlock hint = new TextBlock();
                hint.Text = Resources.Dialog_QrCodeHint;
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
                    imageNote.Text = string.Format(Resources.Dialog_QrCodeErrorFallback, imageError);
                    imageNote.TextWrapping = TextWrapping.Wrap;
                    imageNote.Foreground = new SolidColorBrush(Color.FromRgb(0xA3, 0x31, 0x31));
                    imageNote.Margin = new Thickness(0, 0, 0, 12);
                    root.Children.Add(imageNote);
                }

                TextBlock urlCaption = new TextBlock();
                urlCaption.Text = Resources.Label_ProvisioningUrl;
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
                copyButton.Content = Resources.Button_CopyUrl;
                copyButton.MinWidth = 88;
                copyButton.Height = 30;
                copyButton.Margin = new Thickness(0, 0, 6, 0);
                copyButton.Click += delegate
                {
                    try
                    {
                        Clipboard.SetText(urlLink);
                        copyButton.Content = Resources.Status_Copied;
                    }
                    catch (Exception)
                    {
                        copyButton.Content = Resources.Status_CopyFailed;
                    }
                };

                Button closeButton = new Button();
                closeButton.Content = Resources.Button_Close;
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
