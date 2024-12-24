using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using WixToolset.Dtf.WindowsInstaller;

namespace JenkinsCA
{
    public static class CustomActions
    {
        private static ActionResult LogException(Session session, Exception ex)
        {
            using (Record record = new Record())
            {
                record.FormatString = "Error occurred during installer: [0]";
                record.SetString(1, ex.Message);
                session.Message(InstallMessage.FatalExit, record);
            }
            return ActionResult.Failure;
        }

        [CustomAction]
        public static ActionResult BackupJenkinsXmlFile(Session session)
        {
            ActionResult result = ActionResult.Success;
            try
            {
                DirectoryInfo jenkinsDirPath = new DirectoryInfo(session["JENKINSDIR"]);
                if (jenkinsDirPath.Exists)
                {
                    FileInfo srcPath = new FileInfo(Path.Combine(jenkinsDirPath.FullName, "jenkins.xml"));
                    if (srcPath.Exists)
                    {
                        FileInfo dstPath = new FileInfo(srcPath.FullName + ".backup");
                        int suffix = 0;
                        while (dstPath.Exists)
                        {
                            dstPath = new FileInfo(srcPath.FullName + string.Format(".backup_{0}", suffix));
                            suffix++;
                        }
                        srcPath.CopyTo(dstPath.FullName, true);
                    }
                }
            }
            catch (Exception ex)
            {
                result = LogException(session, ex);
            }
            return result;
        }

        [CustomAction]
        public static ActionResult ValidateJavaHome(Session session)
        {
            ActionResult result = ActionResult.Success;
            try
            {
                DirectoryInfo javaHome = new DirectoryInfo(session["JAVA_HOME"]);
                session["JAVA_EXE_FOUND"] = "0";
                session["JAVA_EXE_VERSION"] = "";
                if (javaHome.Exists)
                {
                    FileInfo javaExe = new FileInfo(Path.Combine(javaHome.FullName, Path.Combine("bin", "java.exe")));
                    if (javaExe.Exists)
                    {
                        session["JAVA_EXE_FOUND"] = "1";
                        FileVersionInfo javaExeVersionInfo = FileVersionInfo.GetVersionInfo(javaExe.FullName);
                        string javaExeVersion = javaExeVersionInfo.FileVersion;
                        session["JAVA_EXE_VERSION"] = javaExeVersion.Substring(0, javaExeVersion.IndexOf(".") - 1);
                    }
                }
            }
            catch (Exception ex)
            {
                result = LogException(session, ex);
            }
            return result;
        }

        [CustomAction]
        public static ActionResult StripJenkinsDir(Session session)
        {
            ActionResult result = ActionResult.Success;
            try
            {
                session["JENKINSDIR_STRIPPED"] = session["JENKINSDIR"].TrimEnd('\\');
            }
            catch (Exception ex)
            {
                result = LogException(session, ex);
            }
            return result;
        }

        [CustomAction]
        public static ActionResult StringTrim(Session session)
        {
            ActionResult result = ActionResult.Success;
            try
            {
                string whiteSpaces = session["STRING_TRIM_WHITESPACES"];
                if (string.IsNullOrEmpty(whiteSpaces))
                {
                    whiteSpaces = " \t";
                }
                session["STRING_TRIM_RESULT"] = session["STRING_TRIM_INPUT"].Trim(whiteSpaces.ToCharArray());
            }
            catch (Exception ex)
            {
                result = LogException(session, ex);
            }
            return result;
        }

        [CustomAction]
        public static ActionResult RegexMatch(Session session)
        {
            ActionResult result = ActionResult.Success;
            try
            {
                string inputString = session["REGEX_MATCH_INPUT_STRING"];
                string patternString = session["REGEX_MATCH_EXPRESSION"];
                session["REGEX_MATCH_RESULT"] = Regex.IsMatch(inputString, patternString, RegexOptions.None) ? "1" : "0";
            }
            catch (Exception ex)
            {
                result = LogException(session, ex);
            }
            return result;
        }

        [CustomAction]
        public static ActionResult CheckCredentials(Session session)
        {
            ActionResult result = ActionResult.Success;
            try
            {
                MessageBox.Show("You are here");
                using (ImpersonatedSession impersonatedSession = new ImpersonatedSession(session))
                {
                    MessageBox.Show("Inside impersonated session");
                    session["LOGON_VALID"] = "0";
                    session["LOGON_ERROR"] = "";
                    session.Log("Checking credentials");
                    MessageBox.Show("Checking credentials");

                    string username = session["LOGON_USERNAME"];
                    string domain = Utilities.SplitUsername(ref username);
                    session.Log(string.Format("username={0}, domain={1}", username, domain));
                    MessageBox.Show(string.Format("username={0}, domain={1}", username, domain));
                    SecureString password = Utilities.SecureStringFromString(session["LOGON_PASSWORD"]);
                    Windows.LOGON32_LOGON_TYPE logonType = Utilities.GetPropertyValue(session, "LOGON_TYPE", Windows.LOGON32_LOGON_TYPE.LOGON32_LOGON_NETWORK);
                    MessageBox.Show(string.Format("logonType = {0}", logonType));

                    Utilities.LogInfo(session, "CheckCredentials", "Userame: {0}", username);
                    Utilities.LogInfo(session, "CheckCredentials", "Password: {0}", password.Length > 0 ? "********" : "<blank>");
                    try
                    {
                        Windows.LogonUser(domain, username, password, logonType);
                        session["LOGON_VALID"] = "1";
                    }
                    catch (Win32Exception ex)
                    {
                        MessageBox.Show(string.Format("Win32 Exception: {0}", ex.Message));
                        session["LOGON_ERROR"] = ex.Message;
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(string.Format("EXCEPTION OCCURRED: {0}", ex.ToString()));
                result = LogException(session, ex);
            }
            return result;
        }

        [CustomAction]
        public static ActionResult CheckMembership(Session session)
        {
            ActionResult result = ActionResult.Success;
            try
            {
                using (ImpersonatedSession impersonatedSession = new ImpersonatedSession(session))
                {
                    Utilities.LogInfo(session, "CheckMembership", "Checking membership");
                    session["LOGON_IS_MEMBER"] = "0";

                    SecurityIdentifier sid = new SecurityIdentifier(session["SID"]);
                    session["LOGON_IS_MEMBER"] = Windows.IsMember(sid) ? "1" : "0";
                }
            }
            catch (Exception ex)
            {
                result = LogException(session, ex);
            }
            return result;
        }

        [CustomAction]
        public static ActionResult BindSocket(Session session)
        {
            ActionResult result = ActionResult.Success;
            try
            {
                session["TCPIP_BIND_SUCCEEDED"] = "0";
                int port = int.Parse(session["TCP_PORT"]);
                Utilities.CheckBool(port < 0 || port > 65536, "");
                string ipAddress = session["TCP_IPADDRESS"];
                if (string.IsNullOrEmpty(ipAddress))
                {
                    ipAddress = "127.0.0.1";
                }

                // we may have a hostname intead
                if (!IPAddress.TryParse(ipAddress, out IPAddress address))
                {
                    IPHostEntry entry = Dns.GetHostEntry(ipAddress);
                    address = entry.AddressList[0];
                }

                Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP);
                IPEndPoint endPoint = new IPEndPoint(address, port);
                s.Bind(endPoint);
                session["TCPIP_BIND_SUCCEEDED"] = "1";
                s.Close();
            }
            catch (Exception ex)
            {
                result = LogException(session, ex);
            }
            return result;
        }

        [CustomAction]
        public static ActionResult DirectoryObjectPicker(Session session)
        {
            ActionResult result = ActionResult.Success;
            try
            {
                Utilities.LogInfo(session, "DirectoryObjectPicker", "Creating an Active Directory object picker dialog.");

                session["DSOP_NAME"] = "";
                session["DSOP_CLASS"] = "";
                session["DSOP_ADSPATH"] = "";
                session["DSOP_UPN"] = "";

                using (DirectoryObjectPickerDialog dlg = new DirectoryObjectPickerDialog())
                {
                    dlg.MultiSelect = false;
                    dlg.DefaultObjectTypes = ObjectTypes.Users;
                    dlg.AllowedObjectTypes = ObjectTypes.Users;


                    dlg.DefaultLocations = dlg.AllowedLocations = Utilities.GetPropertyValue(session, "DSOP_LOCATIONS", Locations.LocalComputer);
                    dlg.AllowedObjectTypes = dlg.DefaultObjectTypes = Utilities.GetPropertyValue(session, "DSOP_OBJECT_TYPES", ObjectTypes.All);

                    if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                    {
                        DirectoryObject obj = dlg.SelectedObject;
                        session["DSOP_NAME"] = obj.Name;
                        session["DSOP_CLASS"] = obj.SchemaClassName;
                        session["DSOP_ADSPATH"] = obj.Path;
                        session["DSOP_UPN"] = obj.Upn;
                    }
                }
            }
            catch (Exception ex)
            {
                result = LogException(session, ex);
            }
            return result;
        }

        [CustomAction]
        public static ActionResult CryptUnprotectDataHex(Session session)
        {
            ActionResult result = ActionResult.Success;
            try
            {
                string hexData = session["CRYPTUNPROTECT_DATA"];
                string entropyHexData = session["CRYPTUNPROTECT_ENTROPY"];
                Windows.CRYPT_FLAGS flags = Utilities.GetPropertyValue(session, "CRYPTUNPROTECT_FLAGS", Windows.CRYPT_FLAGS.CRYPTPROTECT_LOCAL_MACHINE);
                byte[] data = Convert.FromBase64String(hexData);
                byte[] entropy = null;
                if (entropyHexData.Length > 0)
                {
                    entropy = Convert.FromBase64String(entropyHexData);
                }
                byte[] unprotectedData = ProtectedData.Unprotect(data, entropy, flags.IsFlagSet(Windows.CRYPT_FLAGS.CRYPTPROTECT_LOCAL_MACHINE) ? DataProtectionScope.LocalMachine : DataProtectionScope.CurrentUser);
                session["CRYPTUNPROTECT_RESULT"] = Encoding.UTF8.GetString(unprotectedData);
            }
            catch (Exception ex)
            {
                result = LogException(session, ex);
            }
            return result;
        }

        [CustomAction]
        public static ActionResult CryptProtectDataHex(Session session)
        {
            ActionResult result = ActionResult.Success;
            try
            {
                byte[] data = Encoding.UTF8.GetBytes(session["CRYPTPROTECT_DATA"]);
                string entropyData = session["CRYPTPROTECT_ENTROPY"];
                Windows.CRYPT_FLAGS flags = Utilities.GetPropertyValue(session, "CRYPTPROTECT_FLAGS", Windows.CRYPT_FLAGS.CRYPTPROTECT_LOCAL_MACHINE);
                byte[] entropy = null;
                if (!string.IsNullOrEmpty(entropyData))
                {
                    entropy = Encoding.UTF8.GetBytes(entropyData);
                }
                byte[] protectedData = ProtectedData.Protect(data, entropy, flags.IsFlagSet(Windows.CRYPT_FLAGS.CRYPTPROTECT_LOCAL_MACHINE) ? DataProtectionScope.LocalMachine : DataProtectionScope.CurrentUser);
                session["CRYPTPROTECT_RESULT"] = Convert.ToBase64String(protectedData);
            }
            catch (Exception ex)
            {
                result = LogException(session, ex);
            }
            return result;
        }
    }
}
