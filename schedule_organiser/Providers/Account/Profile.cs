using System;
using Couchbase;
using System.Linq;
using System.Diagnostics;
using System.Web.Profile;
using System.Web.Hosting;
using System.Configuration;
using System.Web.Configuration;
using schedule_organiser.Models;
using System.Configuration.Provider;
using System.Collections.Specialized;


namespace schedule_organiser.Providers.Account
{
    public class CouchbaseProfileProvider : ProfileProvider
    {
        // Various variables
        public UserProfile currentUser;
        private readonly string _designDoc;
        //--
        private MachineKeySection machineKey;
        private string eventLog = "Application";
        private string eventSource = "CouchbaseMembershipProvider";
        private string exceptionMessage = "An exception occurred. Please check the Event Log.";

        /// <summary>
        /// Default constructor
        /// </summary>
        public CouchbaseProfileProvider()
        {
            _designDoc = typeof(UserProfile).Name.ToLower().InflectTo().Pluralized;
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
                name = "CouchbaseProfileProvider";

            // Initialize the abstract base class.
            base.Initialize(name, config);

            pApplicationName = GetConfigValue(config["applicationName"], HostingEnvironment.ApplicationVirtualPath);
            pWriteExceptionsToEventLog = Convert.ToBoolean(GetConfigValue(config["writeExceptionsToEventLog"], "true"));

            Configuration cfg = WebConfigurationManager.OpenWebConfiguration(HostingEnvironment.ApplicationVirtualPath);
            machineKey = (MachineKeySection)cfg.GetSection("system.web/machineKey");
            if (machineKey.ValidationKey.Contains("AutoGenerate"))
                throw new ProviderException("Encrypted data is not supported with auto-generated keys.");
            

            //!!!!!!!!!!!!!!!!!!!!!!!
            pWriteExceptionsToEventLog = false;
        }

        #region PROPERTIES
            private string pApplicationName;
            public override string ApplicationName
            {
                get { return pApplicationName; }
                set { pApplicationName = value; }
            }

            private bool pWriteExceptionsToEventLog;
            public bool WriteExceptionsToEventLog
            {
                get { return pWriteExceptionsToEventLog; }
                set { pWriteExceptionsToEventLog = value; }
            }
        #endregion

        #region METHODS
            /// <summary>
            /// 
            /// </summary>
            /// <param name="authenticationOption"></param>
            /// <param name="pageIndex"></param>
            /// <param name="pageSize"></param>
            /// <param name="totalRecords"></param>
            /// <returns></returns>
            public override ProfileInfoCollection GetAllProfiles(ProfileAuthenticationOption authenticationOption, int pageIndex, int pageSize, out int totalRecords)
            {    
                try
                {
                    CouchbaseMembershipProvider m = System.Web.Security.Membership.Provider as CouchbaseMembershipProvider;
                    var profilesRaw = m.GetAllUsers(pageSize, pageIndex, out totalRecords);
               
                    ProfileInfoCollection allProfiles = new ProfileInfoCollection();
                    int counter = 0;
                    foreach (UserMembership currentProfile in profilesRaw)
                    {
                        allProfiles.Add(new ProfileInfo(currentProfile.Email, false, currentProfile.LastActivityDate, currentProfile.LastActivityDate, 0));
                        if (++counter == pageSize)
                            break;
                    }

                    return allProfiles;
                }
                catch (Exception e)
                {
                    if (WriteExceptionsToEventLog)
                    {
                        WriteToEventLog(e, "GetAllProfiles");
                        throw new ProviderException(exceptionMessage);
                    }
                    else throw e;
                }
            }

            /// <summary>
            /// 
            /// </summary>
            /// <param name="authenticationOption"></param>
            /// <param name="userInactiveSinceDate"></param>
            /// <param name="pageIndex"></param>
            /// <param name="pageSize"></param>
            /// <param name="totalRecords"></param>
            /// <returns></returns>
            public override ProfileInfoCollection GetAllInactiveProfiles(ProfileAuthenticationOption authenticationOption, DateTime userInactiveSinceDate, int pageIndex, int pageSize, out int totalRecords)
            {
                try
                {
                    CouchbaseMembershipProvider m = System.Web.Security.Membership.Provider as CouchbaseMembershipProvider;
                    var profilesRaw = m.GetAllUsers(pageSize, pageIndex, out totalRecords);

                    ProfileInfoCollection allProfiles = new ProfileInfoCollection();
                    int counter = 0;
                    foreach (UserMembership currentProfile in profilesRaw)
                        if (currentProfile.LastActivityDate < userInactiveSinceDate)
                        {
                            allProfiles.Add(new ProfileInfo(currentProfile.UserName, false, currentProfile.LastActivityDate, currentProfile.LastActivityDate, 0));
                            if (++counter == pageSize)
                                break;
                        }

                    return allProfiles;
                }
                catch (Exception e)
                {
                    if (WriteExceptionsToEventLog)
                    {
                        WriteToEventLog(e, "GetAllInactiveProfiles");
                        throw new ProviderException(exceptionMessage);
                    }
                    else throw e;
                }
            }

            /// <summary>
            /// 
            /// </summary>
            /// <param name="authenticationOption"></param>
            /// <param name="userInactiveSinceDate"></param>
            /// <returns></returns>
            public override int GetNumberOfInactiveProfiles(ProfileAuthenticationOption authenticationOption, DateTime userInactiveSinceDate)
            {
                try
                {
                    CouchbaseMembershipProvider m = System.Web.Security.Membership.Provider as CouchbaseMembershipProvider;
                    int counter = 0;
                    var profilesRaw = m.GetAllUsers(0, 1, out counter);

                    counter = 0;
                    foreach (UserMembership currentProfile in profilesRaw)
                        if (currentProfile.LastActivityDate < userInactiveSinceDate)
                            counter++;

                    return counter;
                }
                catch (Exception e)
                {
                    if (WriteExceptionsToEventLog)
                    {
                        WriteToEventLog(e, "GetNumberOfInactiveProfiles");
                        throw new ProviderException(exceptionMessage);
                    }
                    else throw e;
                }
            }


            /// <summary>
            /// 
            /// </summary>
            /// <param name="emails"></param>
            /// <returns></returns>
            public override int DeleteProfiles(string[] emails)
            {
                try
                {
                    CouchbaseMembershipProvider m = System.Web.Security.Membership.Provider as CouchbaseMembershipProvider;
                    int counter = 0;

                    foreach(string email in emails)
                    {
                        m.DeleteUser(email, true); //delete membership and everything else
                        counter++;
                    }

                    return counter;
                }
                catch (Exception e)
                {
                    if (WriteExceptionsToEventLog)
                    {
                        WriteToEventLog(e, "DeleteProfiles");
                        throw new ProviderException(exceptionMessage);
                    }
                    else throw e;
                }
            }
            
            /// <summary>
            /// 
            /// </summary>
            /// <param name="profiles"></param>
            /// <returns></returns>
            public override int DeleteProfiles(ProfileInfoCollection profiles)
            {
                try
                {
                    CouchbaseMembershipProvider m = System.Web.Security.Membership.Provider as CouchbaseMembershipProvider;
                    int counter = 0;

                    foreach (ProfileInfo profile in profiles)
                    {
                        m.DeleteUser(profile.UserName, true); //delete membership and everything else
                        counter++;
                    }

                    return counter;
                }
                catch (Exception e)
                {
                    if (WriteExceptionsToEventLog)
                    {
                        WriteToEventLog(e, "DeleteProfiles");
                        throw new ProviderException(exceptionMessage);
                    }
                    else throw e;
                }
            }

            /// <summary>
            /// 
            /// </summary>
            /// <param name="authenticationOption"></param>
            /// <param name="userInactiveSinceDate"></param>
            /// <returns></returns>
            public override int DeleteInactiveProfiles(ProfileAuthenticationOption authenticationOption, DateTime userInactiveSinceDate)
            {
                try
                {
                    int counter;
                    var inactiveProfiles = GetAllInactiveProfiles(authenticationOption, userInactiveSinceDate, 0, 1, out counter);

                    CouchbaseMembershipProvider m = System.Web.Security.Membership.Provider as CouchbaseMembershipProvider;
                    foreach (ProfileInfo profile in inactiveProfiles)
                    {
                        m.DeleteUser(profile.UserName, true); //delete membership and everything else
                        counter++;
                    }

                    return counter;
                }
                catch(Exception e)
                {
                    if (WriteExceptionsToEventLog)
                    {
                        WriteToEventLog(e, "DeleteInactiveProfilesProfiles");
                        throw new ProviderException(exceptionMessage);
                    }
                    else throw e;
                }
            }

            #region MISCELLANEOUS
                /// <summary>
                /// 
                /// </summary>
                /// <param name="authenticationOption"></param>
                /// <param name="usernameToMatch"></param>
                /// <param name="pageIndex"></param>
                /// <param name="pageSize"></param>
                /// <param name="totalRecords"></param>
                /// <returns></returns>
                public override ProfileInfoCollection FindProfilesByUserName(ProfileAuthenticationOption authenticationOption, string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
                {
                    try
                    {
                        ProfileInfoCollection profiles = new ProfileInfoCollection();
                        var profilesMatched = MvcApplication.CouchbaseClient.GetView<UserProfile>(_designDoc, "all", false).
                            Where(s => s.UserName == usernameToMatch);
                        totalRecords = profilesMatched.Count();

                        int counter = 0;
                        profilesMatched = profilesMatched.Skip(pageSize * pageIndex);
                        foreach (UserProfile currentUser in profilesMatched)
                        {
                            profiles.Add(new ProfileInfo(currentUser.UserName, currentUser.IsAnonymous, currentUser.LastActivityDate, currentUser.LastUpdatedDate, 0));
                            if (++counter >= pageIndex)
                                break;
                        }

                        return profiles;
                    }
                    catch (Exception e)
                    {
                        if (WriteExceptionsToEventLog)
                        {
                            WriteToEventLog(e, "FindProfilesByUserName");
                            throw new ProviderException(exceptionMessage);
                        }
                        else throw e;
                    }
                }

                /// <summary>
                /// 
                /// </summary>
                /// <param name="authenticationOption"></param>
                /// <param name="usernameToMatch"></param>
                /// <param name="userInactiveSinceDate"></param>
                /// <param name="pageIndex"></param>
                /// <param name="pageSize"></param>
                /// <param name="totalRecords"></param>
                /// <returns></returns>
                public override ProfileInfoCollection FindInactiveProfilesByUserName(ProfileAuthenticationOption authenticationOption, string usernameToMatch, DateTime userInactiveSinceDate, int pageIndex, int pageSize, out int totalRecords)
                {
                    throw new NotImplementedException();
                }
            #endregion
        #endregion  

        #region Helper Methods
            /// <summary>
            /// 
            /// </summary>
            /// <param name="context"></param>
            /// <param name="collection"></param>
            /// <returns></returns>
            public override SettingsPropertyValueCollection GetPropertyValues(SettingsContext context, SettingsPropertyCollection collection)
            {
                throw new NotImplementedException();
            }

            /// <summary>
            /// 
            /// </summary>
            /// <param name="context"></param>
            /// <param name="collection"></param>
            public override void SetPropertyValues(SettingsContext context, SettingsPropertyValueCollection collection)
            {
                throw new NotImplementedException();
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
}