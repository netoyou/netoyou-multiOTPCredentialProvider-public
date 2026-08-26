using System;
using System.Collections.Generic;
using System.Linq;

namespace MultiOtpManager.Core
{
    public sealed class UserSummary
    {
        public string Name { get; set; }
        public string TokenType { get; set; }
        public string Status { get; set; }
    }

    public sealed class UserDetail
    {
        private readonly Dictionary<string, string> values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public static UserDetail Parse(string text)
        {
            UserDetail detail = new UserDetail();
            if (string.IsNullOrEmpty(text))
            {
                return detail;
            }

            string[] lines = text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string line in lines)
            {
                int separatorIndex = line.IndexOf(':');
                if (separatorIndex <= 0)
                {
                    continue;
                }

                string key = line.Substring(0, separatorIndex).Trim();
                string value = line.Substring(separatorIndex + 1).Trim();
                if (key.Length > 0)
                {
                    detail.values[key] = value;
                }
            }

            return detail;
        }

        public string Username
        {
            get { return GetValue("Information for user", "(unknown)"); }
        }

        public string TokenType
        {
            get { return GetValue("Algorithm", "Not provided"); }
        }

        public string Created
        {
            get { return "Not provided by this CLI version"; }
        }

        public string Status
        {
            get
            {
                string activated = GetValue("Activated", "unknown");
                string locked = GetValue("Locked", "no");
                string delayed = GetValue("Delayed", "no");

                List<string> states = new List<string>();
                states.Add(StringComparer.OrdinalIgnoreCase.Equals(activated, "yes") ? "Activated" : "Disabled");

                if (StringComparer.OrdinalIgnoreCase.Equals(locked, "yes"))
                {
                    states.Add("Locked");
                }

                if (StringComparer.OrdinalIgnoreCase.Equals(delayed, "yes"))
                {
                    states.Add("Delayed");
                }

                return string.Join(", ", states.ToArray());
            }
        }

        public string OtpDigits
        {
            get { return GetValue("OTP digits", "Not provided"); }
        }

        public string Description
        {
            get { return GetValue("Description", string.Empty); }
        }

        public string Email
        {
            get { return GetValue("Email", string.Empty); }
        }

        public string MobilePhone
        {
            get { return GetValue("Mobile phone", string.Empty); }
        }

        public string ToMaskedDisplayText()
        {
            IEnumerable<string> lines = values
                .OrderBy(delegate(KeyValuePair<string, string> item) { return item.Key; })
                .Select(delegate(KeyValuePair<string, string> item)
                {
                    if (IsSensitiveKey(item.Key))
                    {
                        return item.Key + ": ********";
                    }

                    return item.Key + ": " + item.Value;
                });

            return string.Join(Environment.NewLine, lines.ToArray());
        }

        private string GetValue(string key, string fallback)
        {
            string value;
            return values.TryGetValue(key, out value) && !string.IsNullOrWhiteSpace(value) ? value : fallback;
        }

        private static bool IsSensitiveKey(string key)
        {
            string lowerCaseKey = key.ToLowerInvariant();
            return lowerCaseKey.Contains("seed") ||
                   lowerCaseKey.Contains("secret") ||
                   lowerCaseKey.Contains("password") ||
                   lowerCaseKey.Contains("pin");
        }
    }
}
