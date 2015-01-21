using System;
using System.Web;
using System.Linq;
using Newtonsoft.Json;
using System.Web.Hosting;
using System.Diagnostics;
using System.Web.Security;
using Enyim.Caching.Memcached;
using schedule_organiser.Models;
using System.Collections.Generic;
using System.Configuration.Provider;
using System.Collections.Specialized;
using schedule_organiser.Providers.Account;


namespace schedule_organiser.Providers.Account
{
    public class CouchbaseRoleProvider : RoleProvider
    {
        private CouchbaseMembershipProvider m = 
            System.Web.Security.Membership.Provider as CouchbaseMembershipProvider;
        private List<string> allExistingRoles = new List<string>();


        /// <summary>
        /// Initialize all the properties of the provider
        /// </summary>
        /// <param name="name">The name of the RoleProvider</param>
        /// <param name="config">The parameters and their values from web.config</param>
        public override void Initialize(string name, NameValueCollection config)
        {
            if (config == null)
                throw new ArgumentNullException("config");
            if (name == null || name.Length == 0)
                name = "CouchbaseRoleProvider";

            //load the 'allExistingRoles' list with database information
            GetAllRoles();

            //Initialize the abstract base class.
            base.Initialize(name, config);

            applicationName = GetConfigValue(config["applicationName"], HostingEnvironment.ApplicationVirtualPath);
            pWriteExceptionsToEventLog = Convert.ToBoolean(GetConfigValue(config["writeExceptionsToEventLog"], "true"));

            //!!!!!!!!!!!!!!!!!!!!!!!
            pWriteExceptionsToEventLog = false;
        }

        #region PROPERTIES
            private string applicationName;
            public override string ApplicationName
            {
                get { return applicationName; }
                set { applicationName = value; }
            }

            private bool pWriteExceptionsToEventLog;
            public bool WriteExceptionsToEventLog
            {
                get { return pWriteExceptionsToEventLog; }
                set { pWriteExceptionsToEventLog = value; }
            }
            //--
            private string eventLog = "Application";
            private string eventSource = "CouchbaseMembershipProvider";
            private string exceptionMessage = "An exception occurred. Please check the Event Log.";
        #endregion

        #region Roles CRUD
            /// <summary>Create role</summary>
            /// <param name="roleName"></param>
            public override void CreateRole(string roleName)
            {
                try
                {
                    allExistingRoles.Add(roleName);
                    while(!MvcApplication.CouchbaseClient.Store(StoreMode.Set, 
                        "allExistingRoles", JsonConvert.SerializeObject(allExistingRoles)));
                }
                catch (Exception e)
                {
                    if (WriteExceptionsToEventLog)
                    {
                        WriteToEventLog(e, "Create role");
                        throw new ProviderException(exceptionMessage);
                    }
                    else throw e;
                }
            }


            /// <summary>Get all roles</summary>
            /// <returns></returns>
            public override string[] GetAllRoles()
            {
                try
                {
                    var result = MvcApplication.CouchbaseClient.ExecuteGet<string>("allExistingRoles");
                    if (result.HasValue)
                        allExistingRoles = JsonConvert.DeserializeObject<List<string>>(result.Value);
                }
                catch (Exception e)
                {
                    if (WriteExceptionsToEventLog)
                    {
                        WriteToEventLog(e, "Get all roles"); 
                        throw new ProviderException(exceptionMessage);
                    }
                    else throw e;
                }

                return allExistingRoles.ToArray();
            }


            /// <summary></summary>
            /// <param name="oldName"></param>
            /// <param name="newName"></param>
            /// <returns></returns>
            public bool UpdateRole(string oldName, string newName)
            {
                if (oldName == newName)
                    return true;

                try
                {
                    allExistingRoles.Add(newName);
                    allExistingRoles.Remove(allExistingRoles.First(o => o.ToLowerInvariant() == oldName.ToLowerInvariant()));
                    return MvcApplication.CouchbaseClient.Store(StoreMode.Set, "allExistingRoles", JsonConvert.SerializeObject(allExistingRoles));
                }
                catch (Exception e)
                {
                    if (WriteExceptionsToEventLog)
                    {
                        WriteToEventLog(e, "Delete role");
                        throw new ProviderException(exceptionMessage);
                    }
                    else throw e;
                }
            }


            /// <summary>Delete role</summary>
            /// <param name="roleName"></param>
            /// <param name="throwOnPopulatedRole"></param>
            /// <returns>true if role is successfully deleted</returns>
            public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
            {
                try
                {
                    allExistingRoles.Remove(allExistingRoles.First(o => o.ToLowerInvariant() == roleName.ToLowerInvariant()));
                    return MvcApplication.CouchbaseClient.Store(StoreMode.Set, "allExistingRoles", JsonConvert.SerializeObject(allExistingRoles));
                }
                catch (Exception e)
                {
                    if (WriteExceptionsToEventLog)
                    {
                        WriteToEventLog(e, "Delete role");
                        throw new ProviderException(exceptionMessage);
                    }
                    else throw;
                }
            }
        #endregion

        #region Roles' users CRUD
            /// <summary>Add users to roles</summary>
            /// <param name="usernames">An array of the emails of the users to add</param>
            /// <param name="roleNames">An array of the roles to grant</param>
            public override void AddUsersToRoles(string[] emails, string[] roleNames)
            {
                try
                {
                    foreach (string roleName in roleNames)
                    {
                        List<string> usersInRole = GetUsersInRole(roleName).ToList();
                        usersInRole.AddRange(emails);

                        while(!MvcApplication.CouchbaseClient.Store(StoreMode.Set, roleName + "_users", JsonConvert.SerializeObject(usersInRole)));
                    }
                }
                catch (Exception e)
                {
                    if (WriteExceptionsToEventLog)
                    {
                        WriteToEventLog(e, "Add Users To Roles");
                        throw new ProviderException(exceptionMessage);
                    }
                    else throw e;
                }
            }

            /// <summary>NOT IMPLEMENTED</summary>
            /// <param name="roleName"></param>
            /// <param name="usernameToMatch"></param>
            /// <returns></returns>
            public override string[] FindUsersInRole(string roleName, string emailToMatch)
            {
                throw new NotImplementedException();
            }

        
            /// <summary>Get all roles for a specific user</summary>
            /// <param name="email"></param>
            /// <returns></returns>
            public override string[] GetRolesForUser(string email)
            {
                UserMembership up = m.GetUser(email, true) as UserMembership;
                return (from r in up.UserRoles select r.RoleName).ToArray();
            }

            /// <summary>Get all users that belong to a role</summary>
            /// <param name="roleName"></param>
            /// <returns></returns>
            public override string[] GetUsersInRole(string roleName)
            {
                List<string> users = new List<string>();

                try
                {
                    var result = MvcApplication.CouchbaseClient.ExecuteGet<string>(roleName + "_users");
                    if (result.HasValue)
                        users = JsonConvert.DeserializeObject<List<string>>(result.Value);
                }
                catch (Exception e)
                {
                    if (WriteExceptionsToEventLog)
                    {
                        WriteToEventLog(e, "Get Users In Role");
                        throw new ProviderException(exceptionMessage);
                    }
                    else throw e;
                }

                return users.ToArray();
            }


            /// <summary></summary>
            /// <param name="usernames"></param>
            /// <param name="roleNames"></param>
            public override void RemoveUsersFromRoles(string[] emails, string[] roleNames)
            {
                try
                {
                    foreach (string roleName in roleNames)
                    {
                        List<string> usersInRole = GetUsersInRole(roleName).ToList();
                        foreach (string email in emails)
                            usersInRole.Remove(email);

                        while(!MvcApplication.CouchbaseClient.Store(StoreMode.Set, roleName + "_users", JsonConvert.SerializeObject(usersInRole)));
                    }
                }
                catch (Exception e)
                {
                    if (WriteExceptionsToEventLog)
                    {
                        WriteToEventLog(e, "Delete Users From Role");
                        throw new ProviderException(exceptionMessage);
                    }
                    else throw e;
                }
            }
        #endregion

        #region Users' roles CRUD
            /// <summary></summary>
            /// <param name="email"></param>
            /// <param name="roles"></param>
            public void AddRolesToUser(string email, List<Role> roles)
            {
                foreach (var role in roles)
                    if (!RoleExists(role.RoleName))
                        throw new Exception("The role " + role.RoleName + " does not exist!");

                if ((HttpContext.Current.User.Identity as CustomIdentity).Email == email)
                {
                    m.currentUser.UserRoles.AddRange(roles);
                    m.UpdateUser(m.currentUser);
                }
                else
                {
                    UserMembership up = m.GetUser(email, true) as UserMembership;
                    up.UserRoles.AddRange(roles);
                    m.UpdateUser(up);
                }

                AddUsersToRoles(new string[] { email }, (from r in roles select r.RoleName).ToArray());
            }


            /// <summary></summary>
            /// <param name="email"></param>
            /// <returns></returns>
            public List<Role> GetUserRoles(string email)
            {
                if ((HttpContext.Current.User.Identity as CustomIdentity).Email == email)
                    return m.currentUser.UserRoles;

                UserMembership up = m.GetUser(email, false) as UserMembership;
                return up.UserRoles;
            }


            /// <summary></summary>
            /// <param name="email"></param>
            /// <returns></returns>
            public bool UpdateUserRoles(string email, List<Role> updatedRoles)
            {
                if ((HttpContext.Current.User.Identity as CustomIdentity).Email == email)
                {
                    foreach (var updatedRole in updatedRoles)
                    {
                        m.currentUser.UserRoles.RemoveAll(s => s.RoleName == updatedRole.RoleName);
                        m.currentUser.UserRoles.Add(updatedRole);
                    }
                    m.UpdateUser(m.currentUser);
                    return true;
                }

                UserMembership user = m.GetUser(email, false) as UserMembership;
                foreach (var updatedRole in updatedRoles)
                {
                    user.UserRoles.RemoveAll(s => s.RoleName == updatedRole.RoleName);
                    user.UserRoles.Add(updatedRole);
                }
                m.UpdateUser(user);
                return true;
            }

      
            /// <summary></summary>
            /// <param name="email"></param>
            /// <param name="roles"></param>
            public void RemoveRolesFromUser(string email, string[] roles)
            {
                foreach (var role in roles)
                    if (!RoleExists(role))
                        throw new Exception("The role " + role + " does not exist!");

                if ((HttpContext.Current.User.Identity as CustomIdentity).Email == email)
                {
                    m.currentUser.UserRoles.RemoveAll(s => s.RoleName == (from r in roles where r == s.RoleName select r).FirstOrDefault());
                    m.UpdateUser(m.currentUser);
                }
                else
                {
                    UserMembership up = m.GetUser(email, true) as UserMembership;
                    up.UserRoles.RemoveAll(s => s.RoleName == (from r in roles where r == s.RoleName select r).FirstOrDefault());
                    m.UpdateUser(up);
                }

                RemoveUsersFromRoles(new string[] { email }, roles);
            }
        #endregion

        #region Helper Methods
            /// <summary>Checks if user belongs to a given role</summary>
            /// <param name="username"></param>
            /// <param name="roleName"></param>
            /// <returns></returns>
            public override bool IsUserInRole(string email, string roleName)
            {
                if((HttpContext.Current.User.Identity as CustomIdentity).Email == email)
                    return m.currentUser.UserRoles.Exists(s => s.RoleName.ToLowerInvariant() == roleName.ToLowerInvariant());

                return (m.GetUser(email, false) as UserMembership).UserRoles.Exists(s => s.RoleName.ToLowerInvariant() == roleName.ToLowerInvariant());
            }

            /// <summary>Check if role exists.</summary>
            /// <param name="configValue"></param>
            /// <param name="defaultValue"></param>
            /// <returns></returns>
            public override bool RoleExists(string roleName)
            {
                return allExistingRoles.Exists(s => s == roleName); 
            }

            /// <summary>Get config value</summary>
            /// <param name="configValue">The value of the parameter of RoleProvider in web.config</param>
            /// <param name="defaultValue">The value to return if 'configValue' is null or empty</param>
            private string GetConfigValue(string configValue, string defaultValue)
        {
            if (String.IsNullOrEmpty(configValue))
                return defaultValue;

            return configValue;
        }

            /// <summary></summary>
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


    public class Role
    {
        protected Role() { }
        public Role(string roleName)
        {
            RoleName = roleName;
        }
        public Role(string roleName, List<Right> roleRights)
        {
            RoleName = roleName;
            Rights = roleRights;
        }
        //--
        public virtual string RoleName { get; set; }
        public virtual IList<Right> Rights { get; set; }
    }
    public class Right
    {
        protected Right() { }
        public Right(int rightId, string rightName, string description)
        {
            RightId = rightId;
            RightName = rightName;
            Description = description;
        }
        //--
        public virtual int RightId { get; set; }
        public virtual string RightName { get; set; }
        public virtual string Description { get; set; }
    }
}
