using Microsoft.Win32;
using System;

namespace MultiOtpManager.Core
{
    public sealed class CredentialProviderSettings
    {
        public string LogonMode { get; set; }
        public string UnlockMode { get; set; }
        public bool TwoStepHideOtp { get; set; }
    }

    public sealed class CredentialProviderRegistryService
    {
        private const string RegistryPath = "CLSID\\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}";

        public CredentialProviderSettings Load()
        {
            using (RegistryKey classesRoot = OpenClassesRoot())
            using (RegistryKey key = classesRoot.OpenSubKey(RegistryPath))
            {
                if (key == null)
                {
                    return new CredentialProviderSettings
                    {
                        LogonMode = "3d",
                        UnlockMode = "3d",
                        TwoStepHideOtp = false
                    };
                }

                return new CredentialProviderSettings
                {
                    LogonMode = ReadString(key, "cpus_logon", "3d"),
                    UnlockMode = ReadString(key, "cpus_unlock", "3d"),
                    TwoStepHideOtp = ReadInteger(key, "two_step_hide_otp", 0) != 0
                };
            }
        }

        public void Save(CredentialProviderSettings settings)
        {
            if (settings == null)
            {
                throw new ArgumentNullException("settings");
            }

            string logonMode = NormalizeScenario(settings.LogonMode, "3d");
            string unlockMode = NormalizeScenario(settings.UnlockMode, "3d");

            using (RegistryKey classesRoot = OpenClassesRoot())
            using (RegistryKey key = classesRoot.CreateSubKey(RegistryPath))
            {
                key.SetValue("cpus_logon", logonMode, RegistryValueKind.String);
                key.SetValue("cpus_unlock", unlockMode, RegistryValueKind.String);
                key.SetValue("two_step_hide_otp", settings.TwoStepHideOtp ? "1" : "0", RegistryValueKind.String);
            }
        }

        private static RegistryKey OpenClassesRoot()
        {
            RegistryView view = Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default;
            return RegistryKey.OpenBaseKey(RegistryHive.ClassesRoot, view);
        }

        private static string ReadString(RegistryKey key, string name, string fallback)
        {
            object value = key.GetValue(name);
            if (value == null)
            {
                return fallback;
            }

            string text = Convert.ToString(value);
            return string.IsNullOrWhiteSpace(text) ? fallback : text;
        }

        private static int ReadInteger(RegistryKey key, string name, int fallback)
        {
            object value = key.GetValue(name);
            if (value == null)
            {
                return fallback;
            }

            try
            {
                return Convert.ToInt32(value);
            }
            catch (FormatException)
            {
                return fallback;
            }
            catch (InvalidCastException)
            {
                return fallback;
            }
            catch (OverflowException)
            {
                return fallback;
            }
        }

        private static string NormalizeScenario(string value, string fallback)
        {
            string text = (value ?? string.Empty).Trim();
            if (text.Length == 0)
            {
                text = fallback;
            }

            char scope = text[0];
            if (scope != '0' && scope != '1' && scope != '2' && scope != '3')
            {
                scope = fallback[0];
            }

            char availability = text.Length > 1 ? char.ToLowerInvariant(text[text.Length - 1]) : 'd';
            if (availability != 'e' && availability != 'd')
            {
                availability = 'd';
            }

            return string.Concat(scope.ToString(), availability.ToString());
        }
    }
}
