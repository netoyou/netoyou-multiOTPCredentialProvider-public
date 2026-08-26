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

        public Task<ProcessRunResult> VerifyAsync(
            string username,
            string otp,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            ValidateRequiredText(username, "username");
            ValidateRequiredText(otp, "OTP");

            List<string> arguments = new List<string>();
            if (UseVerifySwitch)
            {
                arguments.Add("-verify");
            }

            arguments.Add(username);
            arguments.Add(otp);
            return executor.ExecuteAsync(arguments, timeout, cancellationToken);
        }

        public Task<ProcessRunResult> GetUsersAsync(TimeSpan timeout, CancellationToken cancellationToken)
        {
            List<string> arguments = new List<string>();
            arguments.Add("-userslist");
            return executor.ExecuteAsync(arguments, timeout, cancellationToken);
        }

        public Task<ProcessRunResult> GetUserAsync(
            string username,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            ValidateRequiredText(username, "username");

            List<string> arguments = new List<string>();
            arguments.Add("-user-info");
            arguments.Add(username);
            return executor.ExecuteAsync(arguments, timeout, cancellationToken);
        }

        private static void ValidateRequiredText(string value, string fieldName)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException(fieldName + " is required.", fieldName);
            }
        }
    }
}
