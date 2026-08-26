using System;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Threading;
using System.Threading.Tasks;

namespace MultiOtpManager.Core
{
    public sealed class SystemUserProbe
    {
        public async Task<bool> ExistsAnywhereAsync(string username, TimeSpan timeout, CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                return false;
            }

            try
            {
                using (CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(ct))
                {
                    if (timeout > TimeSpan.Zero)
                    {
                        linked.CancelAfter(timeout);
                    }
                    return await Task.Run<bool>(delegate { return ProbeInternal(username); }, linked.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                return false;
            }
            catch (Exception)
            {
                // Treat any unexpected exception as "unknown" so the caller can still warn instead of crashing.
                return false;
            }
        }

        private static bool ProbeInternal(string username)
        {
            if (ExistsInLocalMachine(username))
            {
                return true;
            }

            if (IsDomainJoined() && ExistsInDomain(username))
            {
                return true;
            }

            return false;
        }

        private static bool ExistsInLocalMachine(string username)
        {
            try
            {
                using (PrincipalContext context = new PrincipalContext(ContextType.Machine))
                {
                    using (UserPrincipal found = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, username))
                    {
                        return found != null;
                    }
                }
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static bool IsDomainJoined()
        {
            try
            {
                using (DirectoryEntry rootDse = new DirectoryEntry("LDAP://rootDSE"))
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

        private static bool ExistsInDomain(string username)
        {
            try
            {
                using (PrincipalContext context = new PrincipalContext(ContextType.Domain))
                {
                    using (UserPrincipal found = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, username))
                    {
                        return found != null;
                    }
                }
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
