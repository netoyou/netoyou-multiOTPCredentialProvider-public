using System;
using System.IO;

namespace MultiOtpManager.Core
{
    /// <summary>
    ///   Per-user preferences persisted as JSON in %LocalAppData%. The file is
    ///   best-effort: corrupted or unreadable settings silently fall back to
    ///   defaults so a malformed disk file cannot stop the app from starting.
    ///   Serialization is hand-written to keep the project free of any
    ///   external JSON dependency (System.Text.Json is not available on
    ///   .NET Framework 4.5.2 without an extra reference assembly).
    /// </summary>
    public sealed class AppSettings
    {
        /// <summary>
        ///   UI culture name (for example "zh-Hans") or empty for system default.
        ///   Looked up via CultureInfo.GetCultureInfo during startup.
        /// </summary>
        public string Language { get; set; } = string.Empty;

        private static readonly string SettingsDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "MultiOtpManager");

        private static readonly string SettingsPath = Path.Combine(
            SettingsDirectory, "settings.json");

        public static string SettingsFilePath
        {
            get { return SettingsPath; }
        }

        public static AppSettings Load()
        {
            try
            {
                if (File.Exists(SettingsPath))
                {
                    string text = File.ReadAllText(SettingsPath);
                    return Parse(text) ?? new AppSettings();
                }
            }
            catch (Exception)
            {
                // Corrupted or unreadable; fall through to defaults.
            }
            return new AppSettings();
        }

        public void Save()
        {
            try
            {
                Directory.CreateDirectory(SettingsDirectory);
                File.WriteAllText(SettingsPath, Serialize());
            }
            catch (Exception)
            {
                // Best-effort persistence; ignore write errors so a read-only
                // profile does not break the rest of the app.
            }
        }

        private string Serialize()
        {
            // Hand-rolled JSON keeps the file readable while avoiding any
            // external JSON dependency. Language is the only field, so a
            // constant template is sufficient.
            return "{\n  \"Language\": \"" + EscapeJsonString(Language ?? string.Empty) + "\"\n}\n";
        }

        private static AppSettings Parse(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return null;
            }

            AppSettings settings = new AppSettings();
            int searchFrom = 0;
            while (searchFrom < text.Length)
            {
                int keyStart = text.IndexOf('"', searchFrom);
                if (keyStart < 0)
                {
                    break;
                }
                int keyEnd = text.IndexOf('"', keyStart + 1);
                if (keyEnd < 0)
                {
                    break;
                }
                string key = text.Substring(keyStart + 1, keyEnd - keyStart - 1);

                int colon = text.IndexOf(':', keyEnd);
                if (colon < 0)
                {
                    break;
                }
                int valueStart = text.IndexOf('"', colon);
                if (valueStart < 0)
                {
                    break;
                }
                int valueEnd = text.IndexOf('"', valueStart + 1);
                if (valueEnd < 0)
                {
                    break;
                }
                string value = UnescapeJsonString(
                    text.Substring(valueStart + 1, valueEnd - valueStart - 1));

                if (key == "Language")
                {
                    settings.Language = value;
                }
                searchFrom = valueEnd + 1;
            }
            return settings;
        }

        private static string EscapeJsonString(string value)
        {
            return value.Replace("\\", "\\\\").Replace("\"", "\\\"");
        }

        private static string UnescapeJsonString(string value)
        {
            return value.Replace("\\\"", "\"").Replace("\\\\", "\\");
        }
    }
}
