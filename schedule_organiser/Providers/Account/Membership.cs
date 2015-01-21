using System;
using Couchbase;
using System.Web;
using System.Net;
using System.Linq;
using System.Text;
using System.Net.Mail;
using Newtonsoft.Json;
using System.Diagnostics;
using System.Web.Hosting;
using System.Web.Security;
using System.Globalization;
using System.Configuration;
using Couchbase.Operations;
using Newtonsoft.Json.Linq;
using System.Threading.Tasks;
using Enyim.Caching.Memcached;
using System.Web.Configuration;
using schedule_organiser.Models;
using System.Security.Principal;
using System.Configuration.Provider;
using Newtonsoft.Json.Serialization;
using System.Collections.Specialized;
using System.Text.RegularExpressions;


namespace schedule_organiser.Providers.Account
{
    public sealed class CouchbaseMembershipProvider : MembershipProvider
    {
        // Various variables
        public UserMembership currentUser;
        private readonly string _designDoc;
        //-- 
        private int newPasswordLength = 8;
        private MachineKeySection machineKey;
        private string eventLog = "Application";
        private string eventSource = "CouchbaseMembershipProvider";
        private string exceptionMessage = "An exception occurred. Please check the Event Log.";

        /// <summary>
        /// Default constructor
        /// </summary>
        public CouchbaseMembershipProvider()
        {
            _designDoc = typeof(UserMembership).Name.ToLower().InflectTo().Pluralized;
        }

        /// <summary>
        /// Initialize all the properties of the provider
        /// </summary>
        /// <param name="name">The name of the RoleProvider</param>
        /// <param name="config">The parameters and their values from web.config</param>
        public override void Initialize(string name, NameValueCollection config)
        {
            // Initialize values from web.config.
            if (config == null)
                throw new ArgumentNullException("config");
            if (name == null || name.Length == 0)
                name = "CouchbaseMembershipProvider";

            // Initialize the abstract base class.
            base.Initialize(name, config);

            ApplicationName = GetConfigValue(config["applicationName"], HostingEnvironment.ApplicationVirtualPath);
            pMaxInvalidPasswordAttempts = Convert.ToInt32(GetConfigValue(config["maxInvalidPasswordAttempts"], "5"));
            pPasswordAttemptWindow = Convert.ToInt32(GetConfigValue(config["passwordAttemptWindow"], "10"));
            pMinRequiredNonAlphanumericCharacters = Convert.ToInt32(GetConfigValue(config["minRequiredNonAlphanumericCharacters"], "0"));
            pMinRequiredPasswordLength = Convert.ToInt32(GetConfigValue(config["minRequiredPasswordLength"], "7"));
            pPasswordStrengthRegularExpression = Convert.ToString(GetConfigValue(config["passwordStrengthRegularExpression"], ""));
            pEnablePasswordReset = Convert.ToBoolean(GetConfigValue(config["enablePasswordReset"], "true"));
            pEnablePasswordRetrieval = Convert.ToBoolean(GetConfigValue(config["enablePasswordRetrieval"], "false"));
            pRequiresQuestionAndAnswer = Convert.ToBoolean(GetConfigValue(config["requiresQuestionAndAnswer"], "true"));
            pRequiresUniqueEmail = Convert.ToBoolean(GetConfigValue(config["requiresUniqueEmail"], "true"));
            pWriteExceptionsToEventLog = Convert.ToBoolean(GetConfigValue(config["writeExceptionsToEventLog"], "true"));
            pPasswordFormat = MembershipPasswordFormat.Encrypted;

            Configuration cfg = WebConfigurationManager.OpenWebConfiguration(HostingEnvironment.ApplicationVirtualPath);
            machineKey = (MachineKeySection)cfg.GetSection("system.web/machineKey");
            if (machineKey.ValidationKey.Contains("AutoGenerate") && PasswordFormat != MembershipPasswordFormat.Clear)
                throw new ProviderException("Encrypted data is not supported with auto-generated keys.");

            
            //!!!!!!!!!!!!!!!!!!!!!!!
            pWriteExceptionsToEventLog = false;
        }

        #region PROPERTIES
            //REQUIRED
            private string pApplicationName;
            private bool pEnablePasswordReset;
            private bool pEnablePasswordRetrieval;
            private bool pRequiresQuestionAndAnswer;
            private bool pRequiresUniqueEmail;
            private int pMaxInvalidPasswordAttempts;
            private int pPasswordAttemptWindow;
            private MembershipPasswordFormat pPasswordFormat;

            public override string ApplicationName
            {
                get { return pApplicationName; }
                set { pApplicationName = value; }
            }
            public override bool EnablePasswordReset
            {
                get { return pEnablePasswordReset; }
            }
            public override bool EnablePasswordRetrieval
            {
                get { return pEnablePasswordRetrieval; }
            }
            public override bool RequiresQuestionAndAnswer
            {
                get { return pRequiresQuestionAndAnswer; }
            }
            public override bool RequiresUniqueEmail
            {
                get { return pRequiresUniqueEmail; }
            }
            public override int MaxInvalidPasswordAttempts
            {
                get { return pMaxInvalidPasswordAttempts; }
            }
            public override int PasswordAttemptWindow
            {
                get { return pPasswordAttemptWindow; }
            }
            public override MembershipPasswordFormat PasswordFormat
            {
                get { return pPasswordFormat; }
            }

            //CUSTOM
            private int pMinRequiredNonAlphanumericCharacters;
            private int pMinRequiredPasswordLength;
            private string pPasswordStrengthRegularExpression;
            private bool pWriteExceptionsToEventLog; // If false, exceptions are thrown to the caller. If true,
                                                    //exceptions are written to the event log.

            public override int MinRequiredNonAlphanumericCharacters
            {
                get { return pMinRequiredNonAlphanumericCharacters; }
            }
            public override int MinRequiredPasswordLength
            {
                get { return pMinRequiredPasswordLength; }
            }
            public override string PasswordStrengthRegularExpression
            {
                get { return pPasswordStrengthRegularExpression; }
            }
            public bool WriteExceptionsToEventLog
            {
                get { return pWriteExceptionsToEventLog; }
                set { pWriteExceptionsToEventLog = value; }
            }
        #endregion

        #region METHODS
            #region Membership CRUD
                /// <summary>
                /// CREATE a new user with the given parameters' data
                /// </summary>
                /// <param name="username">The first part of the email address</param>
                /// <param name="password">User's choosen password</param>
                /// <param name="email">User's choosen email</param>
                /// <param name="securityQuestion">The question the users need to answer to reset their password</param>
                /// <param name="securityAnswer">The answer to the 'securityQuestion' parameter</param>
                /// <param name="isApproved">A bool parameter indicating whether the user's email address is verified</param>
                /// <param name="providerUserKey">The GUID of the new user</param>
                /// <param name="status">A MembershipCreateStatus enum that sheds light on the fail/success of the method</param>
                /// <returns>The UserMembership variable of the new created user</returns>
                public override MembershipUser CreateUser(string username, string password, string email, string securityQuestion, 
                    string securityAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
                {
                    //VALIDATE DATA
                    ValidatePasswordEventArgs args = new ValidatePasswordEventArgs(email, password, true);
                    OnValidatingPassword(args, out status);

                    if (status != MembershipCreateStatus.Success)
                    {
                        WriteToEventLog(args.FailureInformation, "CreateUser");
                        return null;
                    }

                    //CREATE THE NEW USER
                    try
                    {
                        currentUser = new UserMembership(this.Name, providerUserKey, email, password,
                            securityQuestion, securityAnswer, DateTime.UtcNow, null, true, false);

                        var result = MvcApplication.CouchbaseClient.ExecuteStore(StoreMode.Add, currentUser.Email, serializeEncryptAndIgnoreEmail(currentUser), PersistTo.Zero);
                        if (result.Exception != null)
                            throw result.Exception;
                        status = result.Success ? MembershipCreateStatus.Success : MembershipCreateStatus.UserRejected;
                    }
                    catch (Exception e)
                    {
                        status = MembershipCreateStatus.ProviderError;

                        if (WriteExceptionsToEventLog)
                        {
                            WriteToEventLog(e, "CreateUser");
                            throw new ProviderException(exceptionMessage);
                        }
                        else throw e;
                    }

                    return GetUser(email, false);
                }
                
                /// <summary>
                /// CREATE a new user with data from an external provider
                /// </summary>
                /// <param name="currentUser">The MembershipUser create with the provider's data</param>
                /// <param name="status">A MembershipCreateStatus enum that sheds light on the fail/success of the method</param>
                /// <returns>The UserMembership variable of the new created user</returns>
                public MembershipUser CreateExternalUser(UserMembership currentUser, out MembershipCreateStatus status)
                {
                    try
                    {
                        var result = MvcApplication.CouchbaseClient.ExecuteStore(StoreMode.Add, currentUser.Email, serializeEncryptAndIgnoreEmail(currentUser), PersistTo.Zero);
                        if (result.Exception != null)
                            throw result.Exception;
                        status = result.Success ? MembershipCreateStatus.Success : MembershipCreateStatus.UserRejected;
                    }
                    catch (Exception e)
                    {
                        status = MembershipCreateStatus.ProviderError;

                        if (WriteExceptionsToEventLog)
                        {
                            WriteToEventLog(e, "CreateUser");
                            throw new ProviderException(exceptionMessage);
                        }
                        else throw e;
                    }

                    return GetUser(currentUser.Email, false);
                }


                /// <summary>
                /// READ a user from the database based on his email address
                /// </summary>
                /// <param name="email">The user's email address</param>
                /// <param name="userIsOnline">Variable indicating whether the method has been triggered by owner of the given email address or not</param>
                /// <returns>The UserMembership variable of the looked up user</returns>
                public override MembershipUser GetUser(string email, bool userIsOnline)
                {
                    try
                    {
                        var result = MvcApplication.CouchbaseClient.ExecuteGet<string>(email);
                        if (result.HasValue)
                        {
                            UserMembership user = deserializeDecryptAndAddEmail(result.Value, email);

                            if (userIsOnline)
                            {
                                user.LastActivityDate = DateTime.UtcNow;
                                UpdateUser(user);
                            }

                            return user;
                        }

                        return null;
                    }
                    catch (Exception e)
                    {
                        if (WriteExceptionsToEventLog)
                        {
                            WriteToEventLog(e, "GetUser(String, Boolean)");
                            throw new ProviderException(exceptionMessage);
                        }
                        else throw e;
                    }
                }
                
                /// <summary>
                /// READ a user from the database based on his GUID
                /// </summary>
                /// <param name="email">The user's email address</param>
                /// <param name="userIsOnline">Variable indicating whether the method has been triggered by owner of the given email address or not</param>
                /// <returns>The UserMembership variable of the looked up user</returns>
                public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
                {
                    try
                    {
                        string userId = MvcApplication.CouchbaseClient.GetView(_designDoc, "by_guid")
                            .StartKey<string>(Convert.ToBase64String(EncryptPassword(Encoding.Default.GetBytes(providerUserKey.ToString().ToArray()))))
                            .Stale(StaleMode.False)
                            .FirstOrDefault().ItemId;
                        
                        var result = MvcApplication.CouchbaseClient.ExecuteGet<string>(userId);
                        if (result.HasValue)
                        {
                            UserMembership user = deserializeDecryptAndAddEmail(result.Value, userId);

                            if (userIsOnline && user != null)
                            {
                                user.LastActivityDate = DateTime.UtcNow;
                                UpdateUser(user);
                            }
                            return user;
                        }

                        return null;       
                    }
                    catch (Exception e)
                    {
                        if (WriteExceptionsToEventLog)
                        {
                            WriteToEventLog(e, "GetUser(Object, Boolean)");
                            throw new ProviderException(exceptionMessage);
                        }
                        else throw e;
                    }
                }

                /// <summary>
                /// READ all users from the database that have an indexed that falls within a specific range
                /// </summary>
                /// <param name="pageIndex">Indicates the page which is currently visualized</param>
                /// <param name="pageSize">Gives the number of users/page</param>
                /// <param name="totalRecords">Returns the total number of users in the database</param>
                /// <returns>A collection of UserMemberships of the looked up users</returns>
                public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
                {
                    try
                    {

                        var usersRaw = MvcApplication.CouchbaseClient.GetView(_designDoc, "all")
                            .Skip(pageSize * pageIndex); //skip all users to the current one to display
                       
                        MembershipUserCollection users = new MembershipUserCollection();
                        int counter = 0;

                        foreach (IViewRow currentUser in usersRaw)
                        {
                            var result = MvcApplication.CouchbaseClient.ExecuteGet<string>(currentUser.ItemId);
                            if (result.HasValue)
                            {
                                users.Add(deserializeDecryptAndAddEmail(result.Value, currentUser.ItemId));
                                if (++counter == pageSize)
                                    break;
                            }
                        }

                        totalRecords = usersRaw.TotalRows;
                        return users;
                    }
                    catch (Exception e)
                    {
                        if (WriteExceptionsToEventLog)
                        {
                            WriteToEventLog(e, "GetAllUsers");
                            throw new ProviderException(exceptionMessage);
                        }
                        else throw e;
                    }
                }
                
                /// <summary>
                /// READ the total number of users currently online/using the website
                /// </summary>
                /// <returns>An int variable with the exact number</returns>
                public override int GetNumberOfUsersOnline()
                {
                    TimeSpan onlineSpan = new TimeSpan(0, Membership.UserIsOnlineTimeWindow, 0);
                    DateTime compareTime = DateTime.Now.Subtract(onlineSpan);

                    int numOnline = 0;

                    try
                    {
                        int all = 0;
                        var users = GetAllUsers(0, 1, out all);
                        foreach (UserMembership user in users)
                            if (user.LastActivityDate > compareTime)
                                numOnline++;
                    }
                    catch (Exception e)
                    {
                        if (WriteExceptionsToEventLog)
                        {
                            WriteToEventLog(e, "GetNumberOfUsersOnline");
                            throw new ProviderException(exceptionMessage);
                        }
                        else throw e;
                    }

                    return numOnline;
                }
                
                /// <summary>
                /// READ a user's username with the help of his email address
                /// </summary>
                /// <param name="email">The looked up user's email address</param>
                /// <returns>A string with the user's username</returns>
                public override string GetUserNameByEmail(string email)
                {
                    try
                    {
                        return GetUser(email, false).UserName;
                    }
                    catch
                    {
                        return null;
                    }
                }

                
                /// <summary>
                /// UPDATE a user's MembershipProfile
                /// </summary>
                /// <param name="user">The new MemberShipData of the user to update</param>
                public override void UpdateUser(MembershipUser user)
                {
                    try
                    {
                        int i = 0;
                        while ((i++) < 5 && !MvcApplication.CouchbaseClient.Store(StoreMode.Replace, user.Email, serializeEncryptAndIgnoreEmail(user as UserMembership))) ;

                        if (i > 5)
                        {
                            var result = MvcApplication.CouchbaseClient.ExecuteStore(StoreMode.Replace, user.Email, serializeEncryptAndIgnoreEmail(user as UserMembership), PersistTo.Zero);
                            if (result.Exception != null)
                                throw result.Exception;
                        }
                    }
                    catch (Exception e)
                    {
                        if (WriteExceptionsToEventLog)
                        {
                            WriteToEventLog(e, "UpdateUser");
                            throw new ProviderException(exceptionMessage);
                        }
                        else throw;
                    }
                }
                
               
                /// <summary>
                /// DELETE one user's MembershipData
                /// </summary>
                /// <param name="email">The email address of the user to terminate</param>
                /// <param name="deleteAllRelatedData">A bool parameter indicating whether to delete every other document related to this user or not</param>
                /// <returns>A bool value of 'success' or 'failure' to delete the user</returns>
                public override bool DeleteUser(string email, bool deleteAllRelatedData)
                {
                    try
                    {
                        var result = MvcApplication.CouchbaseClient.ExecuteRemove(email, PersistTo.Zero);
                        if (result.Exception != null)
                            throw result.Exception;
                        if (deleteAllRelatedData == true)
                        {
                            //DELETE THE REST
                        }

                        return result.Success;
                    }
                    catch (Exception e)
                    {
                        if (WriteExceptionsToEventLog)
                        {
                            WriteToEventLog(e, "DeleteUser");
                            throw new ProviderException(exceptionMessage);
                        }
                        else throw e;
                    }
                }
            #endregion

            #region User's Password Manipulation Methods
                /// <summary>
                /// Check if the email and password  input of the user match
                /// </summary>
                /// <param name="email">User's given email</param>
                /// <param name="password">User's given password</param>
                /// <returns>'True' if the user is who he says he is or 'False' if he is not</returns>
                public override bool ValidateUser(string email, string password)
                {
                    bool isValid = false;

                    try
                    {
                        currentUser = GetUser(email, true) as UserMembership;
                        if (currentUser.IsLockedOut)
                            return false;

                        if (CheckPassword(password, currentUser.Id, currentUser.ProviderUserKey, false, String.Empty))
                        {
                            if (currentUser.IsApproved)
                            {
                                isValid = true;

                                currentUser.LastLoginDate = DateTime.UtcNow;
                                UpdateUser(currentUser);
                            }
                        }
                        else
                            UpdateFailureCount(email, "password");
                    }
                    catch (Exception e)
                    {
                        if (WriteExceptionsToEventLog)
                        {
                            WriteToEventLog(e, "ValidateUser");
                            throw new ProviderException(exceptionMessage);
                        }
                        else throw e;
                    }

                    return isValid;
                }

                /// <summary>
                /// Change a user's password 
                /// </summary>
                /// <param name="email">The email of the user whose password will be changed</param>
                /// <param name="oldPassword">The former password of the user</param>
                /// <param name="securityAnswer">The answer to the SecurityQuestion he set when he built his account</param>
                /// <returns>'True' if the change was successful, otherwise 'False'</returns>
                public override bool ChangePassword(string email, string oldPassword, string securityAnswer)
                {
                    if (!ValidateUser(email, oldPassword))
                        return false;

                    string newPassword = Membership.GeneratePassword(newPasswordLength, MinRequiredNonAlphanumericCharacters);

                    ValidatePasswordEventArgs args = new ValidatePasswordEventArgs(email, newPassword, false);
                    OnValidatingPassword(args);

                    if (args.Cancel)
                        if (args.FailureInformation != null)
                            throw args.FailureInformation;
                        else
                            throw new MembershipPasswordException("Reset password canceled due to password validation failure.");

                    try
                    {
                        //DECRYPT AND RE-ENCRYPT STRING WITH NEW PASSWORD
                        MvcApplication.SecurityAgent.UserDataEncryption = new Security.RijndaelEncryption(Security.RijndaelEncryption.GetBase64sCryptString(currentUser.ProviderUserKey.ToString(), newPassword, 0), currentUser.ProviderUserKey.ToString());
                        currentUser.Id = Convert.ToBase64String(MvcApplication.SecurityAgent.UserDataEncryption.EncryptStringToBytes(currentUser.ProviderUserKey.ToString()));

                        //CHANGE PASSWORD
                        Security.RijndaelEncryption passwordEncryption = new Security.RijndaelEncryption(Security.RijndaelEncryption.GetBase64sCryptString(currentUser.ProviderUserKey.ToString(), securityAnswer, 0), currentUser.ProviderUserKey.ToString());
                        currentUser.Password = Convert.ToBase64String(passwordEncryption.EncryptStringToBytes(Security.RijndaelEncryption.GetBase64sCryptString(currentUser.ProviderUserKey.ToString(), newPassword, 0)));
                        UpdateUser(currentUser);

                        return true;
                    }
                    catch (Exception e)
                    {
                        if (WriteExceptionsToEventLog)
                        {
                            WriteToEventLog(e, "ChangePassword");
                            throw new ProviderException(exceptionMessage);
                        }
                        else throw e;
                    }
                }

                /// <summary>
                /// Get the user's current password.
                /// This is impossible given the current security model, so it returns an error or an empty string.
                /// </summary>
                /// <param name="email">The email of the user</param>
                /// <param name="securityAnswer">The answer to the SecurityQuestion he set to be able to reset his password</param>
                /// <returns>A string with the user's current password</returns> 
                public override string GetPassword(string email, string securityAnswer)
                {
                    if (!EnablePasswordRetrieval)
                        throw new ProviderException("Password Retrieval Not Enabled.");

                    return String.Empty;
                }

                /// <summary>
                /// Reset a user's password if his identity checks out
                /// </summary>
                /// <param name="email">The user's email address</param>
                /// <param name="answer">The user's answer to his SecurityQuestin which he set to be able to check out his identity in case he forgot his password</param>
                /// <returns>A string with the new password</returns>
                public override string ResetPassword(string email, string answer)
                {
                    if (answer == null && RequiresQuestionAndAnswer)
                    {
                        UpdateFailureCount(email, "passwordAnswer");
                        throw new ProviderException("Password answer required for password reset.");
                    }

                    string newPassword = Membership.GeneratePassword(newPasswordLength, MinRequiredNonAlphanumericCharacters);

                    ValidatePasswordEventArgs args = new ValidatePasswordEventArgs(email, newPassword, false);
                    OnValidatingPassword(args);

                    if (args.Cancel)
                        if (args.FailureInformation != null)
                            throw args.FailureInformation;
                        else
                            throw new MembershipPasswordException("Reset password canceled due to password validation failure.");

                    bool success = false;
                    try
                    {
                        UserMembership currentUser = GetUser(email, false) as UserMembership;
                        if (currentUser == null)
                            throw new MembershipPasswordException("The supplied user name is not found.");
                        if (currentUser.IsLockedOut)
                            throw new MembershipPasswordException("The supplied user is locked out.");

                        if (RequiresQuestionAndAnswer && !CheckPassword(currentUser.Password, currentUser.Id, currentUser.ProviderUserKey, true, answer))
                        {
                            UpdateFailureCount(email, "passwordAnswer");
                            throw new MembershipPasswordException("Incorrect password answer.");
                        }

                        //DECRYPT AND RE-ENCRYPT STRING WITH NEW PASSWORD
                        MvcApplication.SecurityAgent.UserDataEncryption = new Security.RijndaelEncryption(Security.RijndaelEncryption.GetBase64sCryptString(currentUser.ProviderUserKey.ToString(), newPassword, 0), currentUser.ProviderUserKey.ToString());
                        currentUser.Id = Convert.ToBase64String(MvcApplication.SecurityAgent.UserDataEncryption.EncryptStringToBytes(currentUser.ProviderUserKey.ToString()));

                        //CHANGE PASSWORD
                        Security.RijndaelEncryption passwordEncryption = new Security.RijndaelEncryption(Security.RijndaelEncryption.GetBase64sCryptString(currentUser.ProviderUserKey.ToString(), answer, 0), currentUser.ProviderUserKey.ToString());
                        currentUser.Password = Convert.ToBase64String(passwordEncryption.EncryptStringToBytes(Security.RijndaelEncryption.GetBase64sCryptString(currentUser.ProviderUserKey.ToString(), newPassword, 0)));
                        UpdateUser(currentUser);
                        success = true;

                        MailMessage msg = new MailMessage("schedule_organiser@localhost.com", email, "New PASSWORD", newPassword);
                        SmtpClient SMTPServer = new SmtpClient("smtp.live.com", 587) { Credentials = new NetworkCredential("tony.hegyes@hotmail.com", "~MgXqzA$"), DeliveryMethod = SmtpDeliveryMethod.Network, EnableSsl = true };

                        Task sendMail = new Task(new Action(delegate() { SMTPServer.Send(msg); }));
                        sendMail.Start();
                    }
                    catch (Exception e)
                    {
                        if (WriteExceptionsToEventLog)
                        {
                            WriteToEventLog(e, "ResetPassword");
                            throw new ProviderException(exceptionMessage);
                        }
                        else throw e;
                    }

                    if (success)
                        return newPassword;
                    else
                        throw new MembershipPasswordException("User not found, or user is locked out. Password not Reset.");
                }

                /// <summary>
                /// Change a user's SecurityQuestion and SecurityAnswer if he provides the correct password
                /// </summary>
                /// <param name="email">User's email address</param>
                /// <param name="password">User's current VALID password</param>
                /// <param name="newPwdQuestion">The new SecurityQuestion</param>
                /// <param name="newPwdAnswer">The answer to the new SecurityQuestion</param>
                /// <returns>'True' if it succeeded, 'False' otherwise</returns>
                public override bool ChangePasswordQuestionAndAnswer(string email, string password, string newPwdQuestion, string newPwdAnswer)
                {
                    if (!ValidateUser(email, password))
                        return false;

                    try
                    {
                        UserMembership user = new UserMembership(this.Name, currentUser.UserName, currentUser.ProviderUserKey, currentUser.Email,
                                                        newPwdQuestion, currentUser.Comment, currentUser.IsApproved, currentUser.IsLockedOut, currentUser.CreationDate,
                                                        currentUser.LastLoginDate, currentUser.LastActivityDate, currentUser.LastPasswordChangedDate,
                                                        currentUser.LastLockoutDate, currentUser);

                        //CHANGE PASSWORD
                        Security.RijndaelEncryption passwordEncryption = new Security.RijndaelEncryption(Security.RijndaelEncryption.GetBase64sCryptString(currentUser.ProviderUserKey.ToString(), newPwdAnswer, 0), currentUser.ProviderUserKey.ToString());
                        user.Password = Convert.ToBase64String(passwordEncryption.EncryptStringToBytes(Security.RijndaelEncryption.GetBase64sCryptString(currentUser.ProviderUserKey.ToString(), password, 0)));
                        UpdateUser(user);
                        currentUser = user;
                    }
                    catch (Exception e)
                    {
                        if (WriteExceptionsToEventLog)
                        {
                            WriteToEventLog(e, "ChangePasswordQuestionAndAnswer");
                            throw new ProviderException(exceptionMessage);
                        }
                        else throw e;
                    }

                    return true;
                }

                #region Password Validation Helpers
                    /// <summary>
                    /// Checks if the given password returns the right output of the encryption
                    /// </summary>
                    /// <param name="password"></param>
                    /// <param name="encryptedString"></param>
                    /// <param name="providerUserKey"></param>
                    /// <param name="isAnswer"></param>
                    /// <param name="answer"></param>
                    /// <returns></returns>
                    private bool CheckPassword(string password, string encryptedString, object providerUserKey, bool isAnswer, string answer)
                    {
                        string sCryptPassword = string.Empty;
                        if (isAnswer)
                        {
                            Security.RijndaelEncryption passwordEncryption = new Security.RijndaelEncryption(Security.RijndaelEncryption.GetBase64sCryptString(providerUserKey.ToString(), answer, 0), providerUserKey.ToString());
                            sCryptPassword = passwordEncryption.DecryptStringFromBytes(Convert.FromBase64String(password));
                        }

                        Security.RijndaelEncryption Encryptor = new Security.RijndaelEncryption(
                            (isAnswer ? sCryptPassword : Security.RijndaelEncryption.GetBase64sCryptString(providerUserKey.ToString(), password, 0)),
                            providerUserKey.ToString());
                        try
                        {
                            if (providerUserKey.ToString() == Encryptor.DecryptStringFromBytes(Convert.FromBase64String(encryptedString)))
                                return true;
                            return false;
                        }
                        catch
                        {
                            return false;
                        }
                    }

                    /// <summary>
                    /// Validate password only
                    /// </summary>
                    /// <param name="e">Holds the email, password, error message and cancellation token</param>
                    protected override void OnValidatingPassword(ValidatePasswordEventArgs e)
                    {
                        if (e.Password.Length < 6 && e.Password.Length > 100)
                        {   //the password is invalid
                            e.FailureInformation = new HttpException("");
                            e.Cancel = true;
                        }
                    }

                    /// <summary>Validate email and password</summary>
                    /// <param name="e">Holds the email, password, error message and cancellation token</param>
                    /// <param name="status">A MembershipCreateStatus enum that sheds light on the fail/success of the method</param>
                    private void OnValidatingPassword(ValidatePasswordEventArgs e, out MembershipCreateStatus status)
                    {
                        string email = String.Empty;
                        email = Regex.Replace(e.UserName, @"(@)(.+)$", this.DomainMapper,
                            RegexOptions.None, Regex.InfiniteMatchTimeout); // Use IdnMapping class to convert Unicode domain names.

                        if (email == String.Empty)
                        {   //the domain of the email is invalid
                            status = MembershipCreateStatus.InvalidEmail;
                            e.FailureInformation = new HttpException("");
                            e.Cancel = true;
                            return;
                        }

                        if (!Regex.IsMatch(email,
                            @"^(?("")(""[^""]+?""@)|(([0-9a-z]((\.(?!\.))|[-!#\$%&'\*\+/=\?\^`\{\}\|~\w])*)(?<=[0-9a-z])@))" +
                            @"(?(\[)(\[(\d{1,3}\.){3}\d{1,3}\])|(([0-9a-z][-\w]*[0-9a-z]*\.)+[a-z0-9]{2,17}))$", RegexOptions.IgnoreCase, Regex.InfiniteMatchTimeout))
                        {   //the email address is invalid
                            status = MembershipCreateStatus.InvalidEmail;
                            e.FailureInformation = new HttpException("");
                            e.Cancel = true;
                            return;
                        }

                        if (RequiresUniqueEmail && GetUserNameByEmail(email) != null)
                        {   //the email address is not unique
                            status = MembershipCreateStatus.DuplicateEmail;
                            e.FailureInformation = new HttpException("");
                            e.Cancel = true;
                            return;
                        }

                        if (e.Password.Length < 6 && e.Password.Length > 100)
                        {   //the password is invalid
                            status = MembershipCreateStatus.InvalidPassword;
                            e.FailureInformation = new HttpException("");
                            e.Cancel = true;
                            return;
                        }

                        status = MembershipCreateStatus.Success;
                    }
                    private string DomainMapper(Match match)
                    {
                        IdnMapping idn = new IdnMapping();
                        string domainName = match.Groups[2].Value;

                        try
                        {
                            domainName = idn.GetAscii(domainName);
                        }
                        catch (ArgumentException)
                        {
                            return String.Empty;
                        }

                        return match.Groups[1].Value + domainName;
                    }
                #endregion
            #endregion

            #region Miscellaneous
                #region Account Miscellaneous
                    /// <summary>
                    /// A helper method that performs the checks and currentUserdates associated with
                    /// password failure tracking.
                    /// </summary>
                    /// <param name="email"></param>
                    /// <param name="failureType"></param>
                    private void UpdateFailureCount(string email, string failureType)
                    {
                        DateTime windowStart = new DateTime();
                        int failureCount = 0;

                        try
                        {
                            UserMembership currentUser = GetUser(email, true) as UserMembership;

                            switch (failureType)
                            {
                                case "password":
                                    {
                                        failureCount = currentUser.FailedPasswordAttemptCount;
                                        windowStart = currentUser.FailedPasswordAttemptWindowStart;
                                    } break;
                                case "passwordAnswer":
                                    {
                                        failureCount = currentUser.FailedPasswordAnswerAttemptCount;
                                        windowStart = currentUser.FailedPasswordAnswerAttemptWindowStart;
                                    } break;
                            }

                            DateTime windowEnd = windowStart.AddMinutes(PasswordAttemptWindow);

                            if (failureCount == 0 || DateTime.Now > windowEnd)
                            {
                                // First password failure or outside of PasswordAttemptWindow. 
                                // Start a new password failure count from 1 and a new window starting now.

                                switch (failureType)
                                {
                                    case "password":
                                        {
                                            currentUser.FailedPasswordAttemptCount = 1;
                                            currentUser.FailedPasswordAttemptWindowStart = DateTime.UtcNow;
                                        } break;
                                    case "passwordAnswer":
                                        {
                                            currentUser.FailedPasswordAnswerAttemptCount = 1;
                                            currentUser.FailedPasswordAnswerAttemptWindowStart = DateTime.UtcNow;
                                        } break;
                                }

                                try
                                {
                                    UpdateUser(currentUser);
                                }
                                catch
                                {
                                    throw new ProviderException("Unable to currentUserdate failure count and window start.");
                                }
                            }
                            else
                            {
                                if (failureCount++ >= MaxInvalidPasswordAttempts)
                                {
                                    // Password attempts have exceeded the failure threshold. Lock out
                                    // the user.

                                    UserMembership u = new UserMembership(this.Name, currentUser.UserName, currentUser.ProviderUserKey,
                                        currentUser.Email, currentUser.PasswordQuestion, currentUser.Comment, currentUser.IsApproved, true, currentUser.CreationDate,
                                        currentUser.LastLoginDate, currentUser.LastActivityDate, currentUser.LastPasswordChangedDate, currentUser.LastLockoutDate, currentUser);

                                    try
                                    {
                                        UpdateUser(u);
                                    }
                                    catch
                                    {
                                        throw new ProviderException("Unable to lock out user.");
                                    }
                                }
                                else
                                {
                                    // Password attempts have not exceeded the failure threshold. currentUserdate
                                    // the failure counts. Leave the window the same.
                                    switch (failureType)
                                    {
                                        case "password":
                                            {
                                                currentUser.FailedPasswordAttemptCount = failureCount;
                                            } break;
                                        case "passwordAnswer":
                                            {
                                                currentUser.FailedPasswordAnswerAttemptCount = failureCount;
                                            } break;
                                    }

                                    try
                                    {
                                        UpdateUser(currentUser);
                                    }
                                    catch
                                    {
                                        throw new ProviderException("Unable to currentUserdate failure count.");
                                    }
                                }
                            }
                        }
                        catch (Exception e)
                        {
                            if (WriteExceptionsToEventLog)
                            {
                                WriteToEventLog(e, "currentUserdateFailureCount");
                                throw new ProviderException(exceptionMessage);
                            }
                            else throw;
                        }
                    }

                    /// <summary>
                    /// Unlock a locked out user
                    /// </summary>
                    /// <param name="email">The email address of the user to unlock</param>
                    /// <returns>'True' if he can now log in, 'False' otherwise</returns>
                    public override bool UnlockUser(string email)
                    {
                        try
                        {
                            UserMembership user = new UserMembership(this.Name, currentUser.UserName, currentUser.ProviderUserKey, currentUser.Email,
                                                            currentUser.PasswordQuestion, currentUser.Comment, currentUser.IsApproved, false,
                                                            currentUser.CreationDate, currentUser.LastLoginDate, currentUser.LastActivityDate,
                                                            currentUser.LastPasswordChangedDate, DateTime.UtcNow, currentUser);
                            UpdateUser(user); currentUser = user;
                            return true;
                        }
                        catch (Exception e)
                        {
                            if (WriteExceptionsToEventLog)
                            {
                                WriteToEventLog(e, "UnlockUser");
                                throw new ProviderException(exceptionMessage);
                            }
                            else throw e;
                        }
                    }
                #endregion

                /// <summary>
                /// Gets all the users who share a username (in this scenario, just one)
                /// </summary>
                /// <param name="usernameToMatch">The username of the user to return</param>
                /// <param name="pageIndex">The current page viewed of users with this shared username</param>
                /// <param name="pageSize">Number of users/page</param>
                /// <param name="totalRecords">Returns to total number of users who share the same username</param>
                /// <returns>A list of all MembershipUsers to share the same username</returns>
                public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
                {
                    try
                    {
                        MembershipUserCollection users = new MembershipUserCollection();
                        var usersMatched = MvcApplication.CouchbaseClient.GetView<UserMembership>(_designDoc, "all", true).
                            Where(s => s.UserName == usernameToMatch);
                        totalRecords = usersMatched.Count();

                        int counter = 0;
                        usersMatched = usersMatched.Skip(pageSize * pageIndex);
                        foreach (UserMembership currentUser in usersMatched)
                        {
                            users.Add(currentUser);
                            if (++counter >= pageIndex)
                                break;
                        }

                        return users;
                    }
                    catch (Exception e)
                    {
                        if (WriteExceptionsToEventLog)
                        {
                            WriteToEventLog(e, "FindUsersByName");
                            throw new ProviderException(exceptionMessage);
                        }
                        else throw e;
                    }
                }

                /// <summary>
                /// Gets all the users who share an email address (in this scenario, just one)
                /// </summary>
                /// <param name="emailToMatch">The email of the user to return</param>
                /// <param name="pageIndex">The current page viewed of users with this shared email</param>
                /// <param name="pageSize">Number of users/page</param>
                /// <param name="totalRecords">Returns to total number of users who share the same email</param>
                /// <returns>A list of all MembershipUsers to share the same email</returns>
                public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
                {
                    MembershipUserCollection users = new MembershipUserCollection();
                    users.Add(GetUser(emailToMatch, false));
                    totalRecords = users.Count;

                    return users;
                }
            #endregion
        #endregion

        #region HELPER METHODS
            /// <summary>
            /// Helper to serialize, encrypt data and exclude the Email field of UserMembership
            /// </summary>
            /// <param name="obj"></param>
            /// <returns></returns>
            private string serializeEncryptAndIgnoreEmail(UserMembership obj)
            {
                JObject jsonFinal = new JObject();
                JObject jsonObject = JObject.FromObject(obj);
                var contractResolver = new CamelCasePropertyNamesContractResolver();

                foreach (var x in jsonObject.Properties())
                {
                    if (x.Name != "Email")
                        jsonFinal.Add(contractResolver.GetResolvedPropertyName(x.Name),
                                    Convert.ToBase64String(EncryptPassword(Encoding.Default.GetBytes(x.Value.ToString()))));                        
                }

                jsonFinal.Property("type").Value = "usermembership";
                return jsonFinal.ToString();
            }

            /// <summary>
            /// Helper to deserialize, decrypt data and include the Email field of UserMembership
            /// </summary>
            /// <param name="obj"></param>
            /// <returns></returns>
            private UserMembership deserializeDecryptAndAddEmail(string obj, string email)
            {
                JObject jsonFinal = new JObject();
                JObject jsonObject = JObject.Parse(obj);

                foreach (var x in jsonObject.Properties())
                {
                    try
                    {
                        jsonFinal.Add(x.Name, Encoding.Default.GetString(DecryptPassword(Convert.FromBase64String(x.Value.ToString()))));
                    }
                    catch { }
                }

                jsonFinal.Add("email", email);
                jsonFinal.Add("type", "usermembership");
                return JsonConvert.DeserializeObject<UserMembership>(jsonFinal.ToString());
            }

            /// <summary>
            /// A helper function to retrieve config values from the configuration file.
            /// </summary>
            /// <param name="configValue"></param>
            /// <param name="defaultValue"></param>
            /// <returns></returns>
            private string GetConfigValue(string configValue, string defaultValue)
            {
                if (String.IsNullOrEmpty(configValue))
                    return defaultValue;

                return configValue;
            }

            /// <summary>
            /// A helper function that writes exception detail to the event log. Exceptions
            /// are written to the event log as a MvcApplication.SecurityAgent measure to avoid private database
            /// details from being returned to the browser. If a method does not return a status
            /// or boolean indicating the action succeeded or failed, a generic exception is also 
            /// thrown by the caller.
            /// </summary>
            /// <param name="e"></param>
            /// <param name="action"></param>
            private void WriteToEventLog(Exception e, string action)
            {
                EventLog log = new EventLog() { Source = eventSource, Log = eventLog };

                string message = "An exception occurred communicating with the data source.\n\n";
                message += "Action: " + action + "\n\n"; message += "Exception: " + e.ToString();

                log.WriteEntry(message);
            }
        #endregion
    }





    public sealed class CustomIdentity : IIdentity
    {
        private readonly string _username;
        private readonly string _email;

        public CustomIdentity(string email)
        {
            _email = email;
            if (string.IsNullOrWhiteSpace(email))
                return;

            CouchbaseMembershipProvider p = (CouchbaseMembershipProvider)System.Web.Security.Membership.Provider;
            _username = p.GetUser(email, true).UserName;
        }

        public CustomIdentity()
        {
            // TODO: Complete member initialization
        }

        public string Name
        {
            get { return _username; }
        }

        public string Email
        {
            get { return _email; }
        }

        public string AuthenticationType
        {
            get { return "CustomIdentity"; }
        }

        public bool IsAuthenticated
        {
            get { return !string.IsNullOrWhiteSpace(_email); }
        }
    }

    public sealed class CustomPrincipal : IPrincipal
    {
        private readonly CustomIdentity _identity;

        public CustomPrincipal(CustomIdentity identity)
        {
            _identity = identity;
        }

        public bool IsInRole(string role)
        {
            return _identity != null &&
                   _identity.IsAuthenticated &&
                   !string.IsNullOrWhiteSpace(role) &&
                   Roles.IsUserInRole(_identity.Name, role);
        }

        IIdentity IPrincipal.Identity
        {
            get { return _identity; }
        }

        public CustomIdentity Identity
        {
            get { return _identity; }
        }

    }

    public class CustomPrincipalSerializeModel
    {
        public string Name { get; set; }
        public string Email { get; set; }
        public string ExternalProvider { get; set; }
        public string AccessToken { get; set; }
    }
}