using System;
using System.Linq;
using System.Web.Mvc;
using Newtonsoft.Json;
using System.Web.Profile;
using System.Web.Security;
using System.ComponentModel;
using System.Collections.Generic;
using schedule_organiser.Providers;
using schedule_organiser.Providers.Account;
using System.ComponentModel.DataAnnotations;
using CouchbaseModelViews.Framework.Attributes;
using System.Configuration;
using System.Web.Configuration;
using System.Configuration.Provider;
using System.Web.Hosting;
using System.Text;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;
using Enyim.Caching.Memcached;


namespace schedule_organiser.Models
{
    [CouchbaseDesignDoc("usermemberships")]
    [CouchbaseAllView]
    [Serializable]
    public class UserMembership : MembershipUser
    {
        public string Password { get; set; }
        public List<Role> UserRoles { get; set; }
        //--
        [CouchbaseViewKey("by_guid", "id")]
        public string Id { get; set; }
        public string Type { get { return "usermembership"; } }
        public Dictionary<string, object> ExternalProviders { get; set; }
        //--
        public int FailedPasswordAttemptCount { get; set; }
        public int FailedPasswordAnswerAttemptCount { get; set; }
        public DateTime FailedPasswordAttemptWindowStart { get; set; }
        public DateTime FailedPasswordAnswerAttemptWindowStart { get; set; }

        //METHODS
        [JsonConstructor]
        public UserMembership(string providerName, string username, string providerUserKey, string email, string passwordQuestion, string comment, string isApproved, string isLockedOut, string creationDate, string lastLoginDate, string lastActivityDate, string lastPasswordChangedDate, string lastLockoutDate,
            string externalProviders)
            : base(providerName, username, providerUserKey, email, passwordQuestion, comment, Convert.ToBoolean(isApproved), Convert.ToBoolean(isLockedOut), Convert.ToDateTime(creationDate), Convert.ToDateTime(lastLoginDate), Convert.ToDateTime(lastActivityDate), Convert.ToDateTime(lastPasswordChangedDate), Convert.ToDateTime(lastLockoutDate))
        {
            Dictionary<string, object> externalData = new Dictionary<string, object>();

            try
            {
                JObject jsonExternalProviders = JObject.Parse(externalProviders);
                foreach (var x in jsonExternalProviders.Properties())
                {
                    externalData.Add(x.Name, new Dictionary<string, string>());
                    JObject jsonExternalProviderData = JObject.Parse(x.Value.ToString());
                    foreach (var y in jsonExternalProviderData.Properties())
                    {
                        (externalData[x.Name] as Dictionary<string, string>).Add(y.Name, y.Value.ToString());
                    }
                }
            }
            catch { }

            ExternalProviders = externalData;
        }

        //--LOCAL PROVIDER AUTHENTICATION
        public UserMembership(string providername, object providerUserKey, string email, string password,
            string securityQuestion, string securityAnswer, DateTime creationDate, string comment, bool isApproved, bool isLockedOut) :
            base(providername, email.Split('@').First(), providerUserKey, email, securityQuestion, comment, isApproved, isLockedOut,
                creationDate, creationDate, creationDate, creationDate, creationDate)
        {
            Security.RijndaelEncryption passwordEncryption = new Security.RijndaelEncryption(Security.RijndaelEncryption.GetBase64sCryptString(providerUserKey.ToString(), securityAnswer, 0), providerUserKey.ToString());
            Password = Convert.ToBase64String(passwordEncryption.EncryptStringToBytes(Security.RijndaelEncryption.GetBase64sCryptString(providerUserKey.ToString(), password, 0)));

            MvcApplication.SecurityAgent.UserDataEncryption = new Security.RijndaelEncryption(Security.RijndaelEncryption.GetBase64sCryptString(providerUserKey.ToString(), password, 0), providerUserKey.ToString());
            Id = Convert.ToBase64String(MvcApplication.SecurityAgent.UserDataEncryption.EncryptStringToBytes(providerUserKey.ToString()));
            //--
            FailedPasswordAttemptWindowStart = CreationDate;
            FailedPasswordAnswerAttemptWindowStart = CreationDate;
        }

        //--LOCAL PROVIDER/CHANGE SOMETHING 
        public UserMembership(string providerName, string username, object providerUserKey, string email, string passwordQuestion, string comment, bool isApproved, bool isLockedOut, DateTime creationDate, DateTime lastLoginDate, DateTime lastActivityDate, DateTime lastPasswordChangedDate, DateTime lastLockoutDate, UserMembership oldUser) :
            base(providerName, username, providerUserKey, email, passwordQuestion, comment, isApproved, isLockedOut, creationDate, lastLoginDate, lastActivityDate, lastPasswordChangedDate, lastLockoutDate)
        {
            Id = oldUser.Id;
            Password = oldUser.Password;
            UserRoles = oldUser.UserRoles;
            ExternalProviders = oldUser.ExternalProviders;
            //--
            FailedPasswordAttemptCount = oldUser.FailedPasswordAttemptCount;
            FailedPasswordAttemptWindowStart = oldUser.FailedPasswordAttemptWindowStart;
            FailedPasswordAnswerAttemptCount = oldUser.FailedPasswordAnswerAttemptCount;
            FailedPasswordAnswerAttemptWindowStart = oldUser.FailedPasswordAnswerAttemptWindowStart;
        }

        //--EXTERNAL PROVIDER AUTHENTICATION
        public UserMembership(string providername, string username, string email, string comment, bool isApproved,
            bool isLockedOut, string externalAuthKey, object externalAuthData) :
            base(providername, username, Guid.NewGuid(), email, string.Empty, comment, isApproved, isLockedOut,
                DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow.Date, DateTime.MinValue, DateTime.MinValue)
        {
            Id = base.ProviderUserKey.ToString();

            if (ExternalProviders == null)
                ExternalProviders = new Dictionary<string, object>();
            ExternalProviders.Add(externalAuthKey, externalAuthData);
        }
    }

    [CouchbaseDesignDoc("userprofiles")]
    [CouchbaseAllView]
    [Serializable]
    public class UserProfile : ProfileBase
    {
        #region Properties
            public List<string> PublicFields { get; set; }
            public List<string> JustMeFields { get; set; }
            public List<string> FriendsFields { get; set; }
            public List<string> FriendsOfFriendsFields { get; set; }
            public List<string> CustomPermissionFields { get; set; }
            //--
            public BasicProfileModel BasicProfile { get; set; }
            public ExtendedProfileModel ExtendedProfile { get; set; }
            //--
            public string Id { get; set; }
            public string Type { get { return "userprofile"; } }
        #endregion

        public UserProfile()
        {
            Configuration cfg = WebConfigurationManager.OpenWebConfiguration(HostingEnvironment.ApplicationVirtualPath);
            MachineKeySection machineKeyConfig = (MachineKeySection)cfg.GetSection("system.web/machineKey");
            if (machineKeyConfig.ValidationKey.Contains("AutoGenerate"))
                throw new ProviderException("Encrypted data is not supported with auto-generated keys.");

            PublicFields = new List<string>();
            JustMeFields = new List<string>();
            FriendsFields = new List<string>();
            FriendsOfFriendsFields = new List<string>();
            CustomPermissionFields = new List<string>();

            PublicFields.AddRange(new string[] { "FirstName", "FamilyName", "Gender", "Picture" });
            FriendsFields.AddRange(new string[] { "DateOfBirth" });
        }

        [JsonConstructor]
        public UserProfile(string publicFields, string justMeFields, string friendsFields, string friendsOfFriendsFields, string customPermissionFields,
            string propertyValues, string basicProfile, string extendedProfile)
        {
            PublicFields = JsonConvert.DeserializeObject<List<string>>(publicFields);
            JustMeFields = JsonConvert.DeserializeObject<List<string>>(justMeFields);
            FriendsFields = JsonConvert.DeserializeObject<List<string>>(friendsFields);
            FriendsOfFriendsFields = JsonConvert.DeserializeObject<List<string>>(friendsOfFriendsFields);
            CustomPermissionFields = JsonConvert.DeserializeObject<List<string>>(customPermissionFields);

            BasicProfile = JsonConvert.DeserializeObject<BasicProfileModel>(basicProfile);
            ExtendedProfile = JsonConvert.DeserializeObject<ExtendedProfileModel>(extendedProfile);
        }

        public static UserProfile GetUserProfile(string guid)
        {
            return Create(guid) as UserProfile;
        }
        new private static UserProfile Create(string guid)
        {
            try
            {
                var result = MvcApplication.CouchbaseClient.ExecuteGet<string>(guid);
                if (result.HasValue)
                    return deserializeAndDecryptNonPublicData(result.Value, guid);

                return null;
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        public override void Save()
        {
            try
            {
                var result = MvcApplication.CouchbaseClient.ExecuteStore(StoreMode.Set, this.Id, serializeAndEncryptNonPublicData(this));
                if (result.Exception != null)
                    throw result.Exception;
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        #region Security
        /// <summary>
        /// Helper to serialize and encrypt non public data
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        private static string serializeAndEncryptNonPublicData(UserProfile obj)
        {
            JObject jsonFinal = new JObject();
            JObject jsonObject = JObject.FromObject(obj);
            var contractResolver = new CamelCasePropertyNamesContractResolver();
            //--
            foreach (var y in jsonObject.Properties())
            {
                if (y.Name == "Id" || y.Name == "Type")
                    continue;

                if (y.Name == "BasicProfile" || y.Name == "ExtendedProfile")
                {
                    JObject jsonProfileFinal = new JObject();
                    JObject jsonProfile = null;
                    try
                    {
                        jsonProfile = JObject.Parse(y.Value.ToString());
                    }
                    catch { }

                    if (jsonProfile == null)
                        continue;

                    foreach (var x in jsonProfile.Properties())
                    {
                        if (obj.PublicFields.Exists(f => f == x.Name))
                        {
                            jsonProfileFinal.Add(contractResolver.GetResolvedPropertyName(x.Name),
                                Convert.ToBase64String(Encrypt(Encoding.Default.GetBytes(x.Value.ToString()), null)));
                            continue;
                        }

                        if (obj.JustMeFields.Exists(f => f == x.Name))
                        {
                            jsonProfileFinal.Add(contractResolver.GetResolvedPropertyName(x.Name),
                                Convert.ToBase64String(Encrypt(Encoding.Default.GetBytes(x.Value.ToString()), new string[] { "justme" })));
                            continue;
                        }

                        if (obj.FriendsFields.Exists(f => f == x.Name))
                        {
                            jsonProfileFinal.Add(contractResolver.GetResolvedPropertyName(x.Name),
                                Convert.ToBase64String(Encrypt(Encoding.Default.GetBytes(x.Value.ToString()), new string[] { "friends" })));
                            continue;
                        }

                        if (obj.FriendsOfFriendsFields.Exists(f => f == x.Name))
                        {
                            jsonProfileFinal.Add(contractResolver.GetResolvedPropertyName(x.Name),
                                Convert.ToBase64String(Encrypt(Encoding.Default.GetBytes(x.Value.ToString()), new string[] { "friendsoffriends" })));
                            continue;
                        }

                        if (obj.CustomPermissionFields.Exists(f => f == x.Name))
                        {
                            jsonProfileFinal.Add(contractResolver.GetResolvedPropertyName(x.Name),
                                Convert.ToBase64String(Encrypt(Encoding.Default.GetBytes(x.Value.ToString()), new string[] { "custompermission" })));
                            continue;
                        }
                    }

                    jsonFinal.Add(contractResolver.GetResolvedPropertyName(y.Name), jsonProfileFinal.ToString());
                    continue;
                }

                jsonFinal.Add(contractResolver.GetResolvedPropertyName(y.Name),
                    Convert.ToBase64String(Encrypt(Encoding.Default.GetBytes(y.Value.ToString()), null)));
            }

            jsonFinal.Add("type", "userprofile");
            return jsonFinal.ToString();
        }
        /// <summary>
        /// Helper to deserialize and decrypt non public data
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        private static UserProfile deserializeAndDecryptNonPublicData(string obj, string guid)
        {
            string[] permissions = GetRequiredPermissions(guid);

            JObject jsonFinal = new JObject();
            JObject jsonObject = JObject.Parse(obj);

            foreach (var x in jsonObject.Properties())
            {
                if (x.Name == "type")
                    continue;

                if (x.Name == "basicProfile" || x.Name == "extendedProfile")
                {

                    JObject jsonProfileFinal = new JObject();
                    JObject jsonProfile = null;
                    try
                    {
                        jsonProfile = JObject.Parse(x.Value.ToString());
                    }
                    catch { }

                    if (jsonProfile == null)
                        continue;

                    foreach (var y in jsonProfile.Properties())
                    {
                        string z = String.Empty;
                        foreach (string s in permissions)
                        {
                            object byteValue = Decrypt(Convert.FromBase64String(y.Value.ToString()), s == null ? null : (from b in permissions where b == s select b).ToArray());                        
                            if (byteValue != null)
                            {
                                jsonProfileFinal.Add(y.Name, Encoding.Default.GetString(byteValue as byte[]));
                                break;
                            }
                        }
                        
                        
                    }

                    jsonFinal.Add(x.Name, jsonProfileFinal.ToString());
                    continue;
                }

                jsonFinal.Add(x.Name,
                    Encoding.Default.GetString(Decrypt(Convert.FromBase64String(x.Value.ToString()), null)));
            }

            return JsonConvert.DeserializeObject<UserProfile>(jsonFinal.ToString());
        }

        private static byte[] Encrypt(byte[] valueToEncrypt, string[] permissions)
        {
            return MachineKey.Protect(valueToEncrypt, permissions);
        }
        private static byte[] Decrypt(byte[] encryptedValue, string[] permissions)
        {
            try
            {
                return MachineKey.Unprotect(encryptedValue, permissions);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// !!!!WORK
        /// </summary>
        /// <param name="guid"></param>
        /// <returns></returns>
        private static string[] GetRequiredPermissions(object guid)
        {
            string[] permissions = new string[] { null, "justme", "friends", "friendsoffriends", "custompermission" };
            CouchbaseMembershipProvider m = System.Web.Security.Membership.Provider as CouchbaseMembershipProvider;
            if (m.currentUser != null && m.currentUser.Id == guid)
                return permissions;

            UserMembership user = m.GetUser(guid, false) as UserMembership;
            //TO WORK!!!
            return permissions;
        }
        #endregion
    }

    [Serializable]
    public class BasicProfileModel
    {
        [LocalizedRequired("NoData_error", "Account")]
        public string FirstName { get; set; }
        [LocalizedRequired("NoData_error", "Account")]
        public string FamilyName { get; set; }
        //--
        public char Gender { get; set; }
        public DateTime DateOfBirth { get; set; }
        public ProfilePicture Picture { get; set; }

        public BasicProfileModel(string firstName, string familyName)
        {
            FirstName = firstName;
            FamilyName = familyName;
        }

        [JsonConstructor]
        public BasicProfileModel(string firstName, string familyName, string gender, string dateOfBirth, string picture)
        {
            FirstName = firstName;
            FamilyName = familyName;
            Gender = gender[0];
            DateOfBirth = Convert.ToDateTime(dateOfBirth);
            Picture = JsonConvert.DeserializeObject<ProfilePicture>(picture);
        }

        public class ProfilePicture
        {
            public string Path { get; set; }
            public string Origin { get; set; }
            public byte[] Picture { get; set; }

            public ProfilePicture()
            {
            }

            [JsonConstructor]
            public ProfilePicture(string path, string origin, string picture)
            {
                Path = path;
                Origin = origin;
                Picture = Convert.FromBase64String(picture);
            }
        }
    }
    [Serializable]
    public class ExtendedProfileModel
    {
        public ExtendedProfileModel()
        {
        }
    }





    public class LoginModel
    {
        [DataType(DataType.EmailAddress)]
        [LocalizedDisplayName("email_textBox", "Account")]
        [LocalizedRequired("NoData_error", "Account")]
        public string Email { get; set; }

        [DataType(DataType.Password)]
        [LocalizedDisplayName("password_passwordBox", "Account")]
        [LocalizedRequired("NoData_error", "Account")]
        public string Password { get; set; }

        public bool RememberMe { get; set; }
    }
    public class RegisterModel
    {
        [LocalizedRequired("NoData_error", "Account")]
        [LocalizedDisplayName("firstName_textBox", "Account")]
        public string FirstName { get; set; }

        [LocalizedRequired("NoData_error", "Account")]
        [LocalizedDisplayName("lastName_textBox", "Account")]
        public string LastName { get; set; }

        /**/

        [DataType(DataType.EmailAddress)]
        [LocalizedDisplayName("email_textBox", "Account")]
        [LocalizedRequired("emailRequired_error", "Account")]
        public string Email { get; set; }

        [DataType(DataType.EmailAddress)]
        [LocalizedRequired("NoData_error", "Account")]
        [LocalizedDisplayName("confirmEmail_textBox", "Account")]
        [LocalizedCompare(Comparison.MustBeEqualTo, "Email", "emailCompare_error", "Account")]
        public string RepeatEmail { get; set; }

        /**/

        [DataType(DataType.Password)]
        [LocalizedRequired("NoData_error", "Account")]
        [LocalizedDisplayName("password_passwordBox", "Account")]
        [LocalizedStringLength(100, 6, "passwordLength_error", "Account")]
        [LocalizedCompare(Comparison.MustBeNotEqualTo, "Email", "passwordEmailCompare_error", "Account")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [LocalizedRequired("NoData_error", "Account")]
        [LocalizedDisplayName("confirmPassword_passwordBox", "Account")]
        [LocalizedCompare(Comparison.MustBeEqualTo, "Password", "passwordCompare_error", "Account")]
        public string RepeatPassword { get; set; }

        /**/

        [LocalizedRequired("NoData_error", "Account")]
        [LocalizedDisplayName("securityQuestion_textBox", "Account")]
        public string PasswordQuestion { get; set; }

        [LocalizedRequired("NoData_error", "Account")]
        [LocalizedDisplayName("securityAnswer_textBox", "Account")]
        public string PasswordAnswer { get; set; }

        /**/

        public int Day { get; set; }
        public string Month { get; set; }
        public int Year { get; set; }

        public char Sex { get; set; }

        public bool AgreeToTerms_Conditions { get; set; }
    }

    #region CustomValidationAttributes
        [AttributeUsage(AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
        public class LocalizedRequired : RequiredAttribute, IClientValidatable
    {
        public LocalizedRequired(string resourceId, string tableName)
            : base()
        {
            base.ErrorMessage = MvcApplication.LanguageAgent.LanguageDataSet.Tables[tableName].Select("Element_name = '" + resourceId + "'")[0][1] as string;
        }

        public override string FormatErrorMessage(string name)
        {
            return String.Format(base.ErrorMessage, name);
        }

        public override bool IsValid(object value)
        {
            if (value != null && !string.IsNullOrEmpty(value.ToString()))
                return true;

            return false;
        }

        public IEnumerable<ModelClientValidationRule> GetClientValidationRules(ModelMetadata metadata, ControllerContext context)
        {
            var clientValidationRule = new ModelClientValidationRule()
            {
                ErrorMessage = FormatErrorMessage(metadata.GetDisplayName()),
                ValidationType = "localizedrequired"
            };

            return new[] { clientValidationRule };
        }
    }

        [AttributeUsage(AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
        public class LocalizedDisplayNameAttribute : DisplayNameAttribute
        {
            public LocalizedDisplayNameAttribute(string resourceId, string tableName)
                : base(MvcApplication.LanguageAgent.LanguageDataSet.Tables[tableName].Select("Element_name = '" + resourceId + "'")[0][1] as string)
            { }
        }

        public enum Comparison { MustBeEqualTo, MustBeNotEqualTo }
        [AttributeUsage(AttributeTargets.Property, AllowMultiple = true, Inherited = true)]
        public class LocalizedCompareAttribute : ValidationAttribute, IClientValidatable
        {
            private string _otherPropertyName;
            private Comparison _comparison;

            public LocalizedCompareAttribute(Comparison comparison, string otherProperty, string resourceId, string tableName)
                : base()
            {
                _comparison = comparison;
                _otherPropertyName = otherProperty;
                base.ErrorMessage = MvcApplication.LanguageAgent.LanguageDataSet.Tables[tableName].Select("Element_name = '" + resourceId + "'")[0][1] as string;
            }

            protected override ValidationResult IsValid(object value, ValidationContext validationContext)
            {
                var basePropertyInfo = validationContext.ObjectType.GetProperty(_otherPropertyName);
                var _otherPropertyValue = (string)basePropertyInfo.GetValue(validationContext.ObjectInstance, null);

                switch (_comparison)
                {
                    case Comparison.MustBeEqualTo:
                        {
                            if (String.Compare(_otherPropertyValue, value as string) != 0)
                                return new ValidationResult(base.ErrorMessage);
                        } break;
                    case Comparison.MustBeNotEqualTo:
                        {
                            if (String.Compare(_otherPropertyValue, value as string) == 0)
                                return new ValidationResult(base.ErrorMessage);
                        } break;
                }

                return ValidationResult.Success;
            }

            public IEnumerable<ModelClientValidationRule> GetClientValidationRules(ModelMetadata metadata, ControllerContext context)
            {
                var clientValidationRule = new ModelClientValidationRule()
                {
                    ErrorMessage = base.ErrorMessage,
                    ValidationType = "localizedcompare"
                };

                clientValidationRule.ValidationParameters.Add("otherproperty", _otherPropertyName);
                clientValidationRule.ValidationParameters.Add("comp", _comparison.ToString().ToLower());

                return new[] { clientValidationRule };
            }
        }

        [AttributeUsage(AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
        public class LocalizedStringLengthAttribute : ValidationAttribute, IClientValidatable
    {
        private int _minimumLength, _maximumLength;

        public LocalizedStringLengthAttribute(int maximumLength, int minimumLength, string resourceId, string tableName)
            : base()
        {
            _maximumLength = maximumLength;
            _minimumLength = minimumLength;
            base.ErrorMessage = MvcApplication.LanguageAgent.LanguageDataSet.Tables[tableName].Select("Element_name = '" + resourceId + "'")[0][1] as string;
        }

        public override string FormatErrorMessage(string name)
        {
            return String.Format(base.ErrorMessage, _minimumLength, _maximumLength);
        }

        public override bool IsValid(object value)
        {
            return (value as string).Length <= _maximumLength && (value as string).Length >= _minimumLength;
        }

        public IEnumerable<ModelClientValidationRule> GetClientValidationRules(ModelMetadata metadata, ControllerContext context)
        {
            var clientValidationRule = new ModelClientValidationRule()
            {
                ErrorMessage = FormatErrorMessage(metadata.GetDisplayName()),
                ValidationType = "localizedstringlength",
            };

            clientValidationRule.ValidationParameters.Add("min", _minimumLength);
            clientValidationRule.ValidationParameters.Add("max", _maximumLength);

            return new[] { clientValidationRule };
        }
    }
    #endregion

    /*

    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, Inherited = true, AllowMultiple = true)]
    public class FacebookAuthorizeAttribute : AuthorizeAttribute
    {
        protected override bool AuthorizeCore(HttpContextBase httpContext)
        {
            var isAuthenticated = base.AuthorizeCore(httpContext);
            if (isAuthenticated) 
            {
                string cookieName = FormsAuthentication.FormsCookieName;
                if (!httpContext.User.Identity.IsAuthenticated ||
                    httpContext.Request.Cookies == null || 
                    httpContext.Request.Cookies[cookieName] == null)
                {
                    return false;
                }

                var authCookie = httpContext.Request.Cookies[cookieName];
                var authTicket = FormsAuthentication.Decrypt(authCookie.Value);

                CustomPrincipalSerializeModel userData = 
                    JsonConvert.DeserializeObject<CustomPrincipalSerializeModel>(authTicket.UserData);

          
                IPrincipal userPrincipal = ... create some custom implementation
                                               and store the web service token as property

                // Inject the custom principal in the HttpContext
                httpContext.User = userPrincipal;
             
            }
            return isAuthenticated;
        }
     *  
    }
     *   */
}
