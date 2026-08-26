using MultiOtpManager.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace MultiOtpManager
{
    public partial class MainWindow
    {
        private readonly MultiOtpCliClient cliClient;
        private readonly CredentialProviderRegistryService registryService;
        private CancellationTokenSource currentOperationCancellation;
        private bool refreshingUsers;

        public MainWindow()
        {
            InitializeComponent();
            cliClient = new MultiOtpCliClient();
            registryService = new CredentialProviderRegistryService();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            ExecutablePathText.Text = cliClient.ExecutablePath;
            ExecutablePathText.ToolTip = cliClient.ExecutablePath;
            LoadSettings();
        }

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

        private async void RefreshUsersButton_Click(object sender, RoutedEventArgs e)
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

                if (result.ExitCode != 0 && result.ExitCode != 19)
                {
                    UserDetailBox.Text = BuildCombinedOutput(result);
                    SetStatus("User list command failed. Exit code: " + result.ExitCode);
                    return;
                }

                List<string> users = result.StandardOutput
                    .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(delegate(string line) { return line.Trim(); })
                    .Where(delegate(string line) { return line.Length > 0; })
                    .ToList();

                UsersListBox.ItemsSource = users
                    .Select(delegate(string user) { return new UserSummary { Name = user }; })
                    .ToList();

                if (UsersListBox.Items.Count == 0)
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

            try
            {
                ProcessRunResult result = await RunOperationAsync(
                    "load user details",
                    delegate(CancellationToken token)
                    {
                        return cliClient.GetUserAsync(summary.Name, GetTimeout(), token);
                    });

                if (result.ExitCode != 0 && result.ExitCode != 19)
                {
                    ClearUserDetail();
                    UserDetailBox.Text = BuildCombinedOutput(result);
                    SetStatus("User detail command failed. Exit code: " + result.ExitCode);
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
                VerifyResultText.Foreground = FindResource("GoodColor") as System.Windows.Media.Brush;
                VerifyResultText.Text = "Authentication accepted.";
                SetStatus("Authentication accepted.");
                return;
            }

            VerifyResultText.Foreground = FindResource("BadColor") as System.Windows.Media.Brush;
            VerifyResultText.Text = "Authentication refused. " + GetFriendlyExitText(result.ExitCode);
            SetStatus("Authentication refused. Exit code: " + result.ExitCode);
        }

        private void ShowVerifyFailure(string message)
        {
            VerifyResultText.Foreground = FindResource("BadColor") as System.Windows.Media.Brush;
            VerifyResultText.Text = message;
            SetStatus(message);
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

        private void SetBusy(bool busy, string status)
        {
            VerifyButton.IsEnabled = !busy;
            RefreshUsersButton.IsEnabled = !busy;
            SaveSettingsButton.IsEnabled = !busy;
            UsersListBox.IsEnabled = !busy;
            CancelButton.IsEnabled = busy;
            SetStatus(status);
        }

        private void SetStatus(string status)
        {
            StatusText.Text = status;
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
                case 20:
                    return "The user is blacklisted.";
                case 21:
                    return "The user does not exist.";
                case 22:
                    return "The user already exists.";
                case 23:
                    return "The token algorithm is invalid.";
                case 24:
                    return "The user or token is locked.";
                case 25:
                    return "The user is delayed.";
                case 26:
                    return "The token was reused.";
                case 27:
                    return "Token synchronization failed.";
                case 30:
                    return "A required parameter is missing.";
                case 38:
                    return "The user is disabled.";
                case 39:
                    return "The operation was cancelled.";
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

            return "The operation failed. " + exception.GetType().Name + ".";
        }
    }
}
