using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MultiOtpManager.Core
{
    public sealed class ProcessRunResult
    {
        public int ExitCode { get; set; }
        public string StandardOutput { get; set; }
        public string StandardError { get; set; }
    }

    public sealed class MultiOtpProcessExecutor
    {
        private const int FlushTimeoutMilliseconds = 2000;

        public MultiOtpProcessExecutor(string executablePath)
        {
            if (string.IsNullOrWhiteSpace(executablePath))
            {
                throw new ArgumentException("The executable path is required.", "executablePath");
            }

            ExecutablePath = Path.GetFullPath(executablePath);
        }

        public string ExecutablePath { get; private set; }

        public static string BuildArguments(IEnumerable<string> arguments)
        {
            if (arguments == null)
            {
                throw new ArgumentNullException("arguments");
            }

            string[] escapedArguments = arguments
                .Select(EscapeArgument)
                .ToArray();

            return string.Join(" ", escapedArguments);
        }

        public static string EscapeArgument(string argument)
        {
            if (argument == null)
            {
                throw new ArgumentNullException("argument");
            }

            if (argument.Length == 0)
            {
                return "\"\"";
            }

            StringBuilder escaped = new StringBuilder(argument.Length + 8);
            int trailingBackslashes = 0;

            foreach (char character in argument)
            {
                if (character == '\\')
                {
                    trailingBackslashes++;
                    continue;
                }

                if (character == '"')
                {
                    escaped.Append('\\', (trailingBackslashes * 2) + 1);
                    escaped.Append('"');
                }
                else
                {
                    escaped.Append('\\', trailingBackslashes);
                    escaped.Append(character);
                }

                trailingBackslashes = 0;
            }

            if (trailingBackslashes > 0)
            {
                escaped.Append('\\', trailingBackslashes * 2);
            }

            escaped.Insert(0, '"');
            escaped.Append('"');
            return escaped.ToString();
        }

        public async Task<ProcessRunResult> ExecuteAsync(
            IList<string> arguments,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            if (arguments == null)
            {
                throw new ArgumentNullException("arguments");
            }

            if (!File.Exists(ExecutablePath))
            {
                throw new FileNotFoundException("multiotp.exe was not found beside MultiOtpManager.exe.", ExecutablePath);
            }

            cancellationToken.ThrowIfCancellationRequested();

            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = ExecutablePath;
            startInfo.Arguments = BuildArguments(arguments);
            startInfo.WorkingDirectory = Path.GetDirectoryName(ExecutablePath);
            startInfo.UseShellExecute = false;
            startInfo.CreateNoWindow = true;
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardError = true;
            startInfo.StandardOutputEncoding = Encoding.UTF8;
            startInfo.StandardErrorEncoding = Encoding.UTF8;

            using (Process process = new Process())
            using (CancellationTokenSource timeoutSource = new CancellationTokenSource())
            using (CancellationTokenSource linkedSource = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                timeoutSource.Token))
            {
                process.StartInfo = startInfo;
                process.EnableRaisingEvents = true;

                StringBuilder standardOutput = new StringBuilder();
                StringBuilder standardError = new StringBuilder();
                object outputLock = new object();
                TaskCompletionSource<object> exitWaiter = new TaskCompletionSource<object>();
                bool timedOut = false;

                EventHandler exitedHandler = delegate
                {
                    exitWaiter.TrySetResult(null);
                };

                DataReceivedEventHandler outputHandler = delegate(object sender, DataReceivedEventArgs eventArgs)
                {
                    if (eventArgs.Data != null)
                    {
                        lock (outputLock)
                        {
                            standardOutput.AppendLine(eventArgs.Data);
                        }
                    }
                };

                DataReceivedEventHandler errorHandler = delegate(object sender, DataReceivedEventArgs eventArgs)
                {
                    if (eventArgs.Data != null)
                    {
                        lock (outputLock)
                        {
                            standardError.AppendLine(eventArgs.Data);
                        }
                    }
                };

                process.Exited += exitedHandler;
                process.OutputDataReceived += outputHandler;
                process.ErrorDataReceived += errorHandler;

                try
                {
                    process.Start();
                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();

                    if (timeout > TimeSpan.Zero)
                    {
                        timeoutSource.CancelAfter(timeout);
                    }

                    using (CancellationTokenRegistration registration = linkedSource.Token.Register(delegate
                    {
                        timedOut = !cancellationToken.IsCancellationRequested;
                        TryStopProcess(process);
                        exitWaiter.TrySetCanceled();
                    }))
                    {
                        await exitWaiter.Task.ConfigureAwait(false);
                    }

                    process.WaitForExit(FlushTimeoutMilliseconds);

                    string output;
                    string error;

                    lock (outputLock)
                    {
                        output = standardOutput.ToString();
                        error = standardError.ToString();
                    }

                    return new ProcessRunResult
                    {
                        ExitCode = process.ExitCode,
                        StandardOutput = output,
                        StandardError = error
                    };
                }
                catch (OperationCanceledException)
                {
                    if (timedOut)
                    {
                        throw new TimeoutException("The multiOTP command timed out.");
                    }

                    throw;
                }
                finally
                {
                    process.Exited -= exitedHandler;
                    process.OutputDataReceived -= outputHandler;
                    process.ErrorDataReceived -= errorHandler;
                    TryWaitAfterCancellation(process);
                }
            }
        }

        private static void TryStopProcess(Process process)
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill();
                }
            }
            catch (InvalidOperationException)
            {
            }
            catch (System.ComponentModel.Win32Exception)
            {
            }
        }

        private static void TryWaitAfterCancellation(Process process)
        {
            try
            {
                if (!process.HasExited)
                {
                    process.WaitForExit(FlushTimeoutMilliseconds);
                }
            }
            catch (InvalidOperationException)
            {
            }
            catch (System.ComponentModel.Win32Exception)
            {
            }
        }
    }
}
