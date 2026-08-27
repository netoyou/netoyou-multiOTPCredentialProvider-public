using System.Globalization;
using System.IO;
using System.Threading;
using System.Windows;
using MultiOtpManager.Core;

namespace MultiOtpManager
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            // Pick the UI culture before any window is created so that
            // MainWindow's {x:Static p:Resources.Key} bindings resolve against
            // the chosen language.
            AppSettings settings = AppSettings.Load();

            // First-run auto-detection: if there is no settings file on disk,
            // guess the best matching built-in language from the system UI
            // culture and persist the choice so the picker reflects it later.
            if (!File.Exists(AppSettings.SettingsFilePath))
            {
                settings.Language = GuessInitialLanguage();
                settings.Save();
            }

            ApplyLanguage(settings.Language);

            base.OnStartup(e);
        }

        private static string GuessInitialLanguage()
        {
            CultureInfo current = CultureInfo.CurrentUICulture;
            string name = current != null ? current.Name : string.Empty;

            // Anything in the zh family maps to Simplified Chinese; otherwise
            // fall through to English, which is the Resources.resx fallback.
            if (name.StartsWith("zh", System.StringComparison.OrdinalIgnoreCase))
            {
                return "zh-Hans";
            }
            return "en";
        }

        private static void ApplyLanguage(string cultureName)
        {
            if (string.IsNullOrEmpty(cultureName))
            {
                return;
            }

            try
            {
                CultureInfo culture = CultureInfo.GetCultureInfo(cultureName);
                CultureInfo.DefaultThreadCurrentUICulture = culture;
                Thread.CurrentThread.CurrentUICulture = culture;
            }
            catch (CultureNotFoundException)
            {
                // Unknown culture name in settings: ignore and fall back to the
                // process default, which will resolve to Resources.resx.
            }
        }
    }
}
