using System;
using Facebook;
using System.IO;
using System.Web;
using System.Net;
using System.Linq;
using System.Data;
using System.Drawing;
using System.Web.Mvc;
using System.Net.Mail;
using Newtonsoft.Json;
using System.Web.Profile;
using System.Web.Security;
using System.Configuration;
using System.Globalization;
using System.Threading.Tasks;
using schedule_organiser.Models;
using System.Collections.Generic;
using schedule_organiser.Providers.Account;


namespace schedule_organiser.Controllers
{
    public class AccountController : Controller
    {
        //
        // GET: /Account/Login

        [AllowAnonymous]
        public ActionResult Login()
        {
            return View();
        }

        //
        // POST: /Account/Login

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Login(LoginModel model)
        {
            CouchbaseMembershipProvider m = System.Web.Security.Membership.Provider as CouchbaseMembershipProvider;
            m.currentUser = m.GetUser(model.Email, false) as UserMembership;
            if (m.currentUser == null) //users doesn't exist in our records
            {
                ModelState.AddModelError(String.Empty, MvcApplication.GetDisplayNameFor("accountNotFound_error", "Account"));
                return View(model);
            }
            if (m.currentUser.Password == null) //no local password AKA the account is made available through an external provider
            {
                ModelState.AddModelError(String.Empty, MvcApplication.GetDisplayNameFor("localAccountNotFound_error", "Account"));
                return View(model);
            }

            //setting up a cookie with custom information
            if (ModelState.IsValid && m.ValidateUser(model.Email, model.Password))
            {
                CustomPrincipalSerializeModel serializeModel = new CustomPrincipalSerializeModel(){ 
                    Email = m.currentUser.Email, Name = m.currentUser.UserName };

                FormsAuthenticationTicket authTicket = new FormsAuthenticationTicket(1, model.Email, DateTime.Now,
                    DateTime.Now.AddMinutes(FormsAuthentication.Timeout.TotalMinutes), model.RememberMe, JsonConvert.SerializeObject(serializeModel));
                HttpCookie faCookie = new HttpCookie(FormsAuthentication.FormsCookieName,
                    FormsAuthentication.Encrypt(authTicket));
                Response.AppendCookie(faCookie);

                return RedirectToAction("Index", "Main");
            }

            // If we got this far, something failed, redisplay form
            ModelState.AddModelError(String.Empty, MvcApplication.GetDisplayNameFor("wrongData_error", "Account"));
            return View(model);
        }

        //
        // POST: /Account/FacebookLoginCallback

        [HttpPost]
        [AllowAnonymous]
        public ActionResult FacebookLoginCallback(String accessToken)
        {
          
            var client = new FacebookClient();
            dynamic result = client.Get("/oauth/access_token", new
            {
                grant_type = "fb_exchange_token",
                client_id = ConfigurationManager.AppSettings["fb_key"],
                client_secret = ConfigurationManager.AppSettings["fb_secret"],
                fb_exchange_token = accessToken
            });

            BasicProfileModel.ProfilePicture pic = null;
            dynamic userFB = client.Get("/me", new { fields = "id, name, username, email, birthday, gender, first_name, last_name", access_token = result.access_token });
            dynamic userFB_pic = client.Get("/me/picture", new { type = "large", redirect = "false", access_token = result.access_token });
           
            //LOG HIM IN IF HE ALREADY HAS AN (EXTERNAL) ACCOUNT
            CouchbaseMembershipProvider m = System.Web.Security.Membership.Provider as CouchbaseMembershipProvider;
            CouchbaseProfileProvider p = Profile.Providers["CouchbaseProfileProvider"] as CouchbaseProfileProvider;
            m.currentUser = m.GetUser(userFB.email, false) as UserMembership;

            if (m.currentUser != null) //user found
            {
                p.currentUser = UserProfile.GetUserProfile(m.currentUser.Id);
                if (m.currentUser.ExternalProviders == null || m.currentUser.ExternalProviders.Count == 0) //add external provider data, if he already has a local account
                {
                    m.currentUser.ExternalProviders = new Dictionary<string, object>();
                    m.currentUser.ExternalProviders.Add("facebook", new { ProviderUserId = userFB.id });
                    m.UpdateUser(m.currentUser);
                }
                if (p.currentUser.BasicProfile.Picture == null || (p.currentUser.BasicProfile.Picture.Path != userFB_pic.data.url && p.currentUser.BasicProfile.Picture.Origin == "facebook"))
                {
                    if(!userFB_pic.data.is_silhouette)
                        using (WebClient Client = new WebClient())
                        {
                            pic = new BasicProfileModel.ProfilePicture()
                            {
                                Origin = "facebook",
                                Path = userFB_pic.data.url,
                                Picture = Client.DownloadData(userFB_pic.data.url as string)
                            };
                        }
                    p.currentUser.BasicProfile.Picture = pic;
                    p.currentUser.Save();
                }

                return FacebookLocalAuth(result.access_token);
            }

            // User is new, get their data and log him/her in
            if (!userFB_pic.data.is_silhouette)
                using (WebClient Client = new WebClient())
                {
                    pic = new BasicProfileModel.ProfilePicture()
                    {
                        Origin = "facebook",
                        Path = userFB_pic.data.url,
                        Picture = Client.DownloadData(userFB_pic.data.url as string)
                    };
                }

            m.currentUser = new UserMembership(m.Name, userFB.username, userFB.email, null, true, false,
                "facebook", new { ProviderUserId = userFB.id });

            MembershipCreateStatus status;
            m.CreateExternalUser(m.currentUser, out status);
            if (status != MembershipCreateStatus.Success)
                return Json(new { redirect = false, error = ErrorCodeToString(status) }, JsonRequestBehavior.DenyGet);

            p.currentUser = new UserProfile()
            {
                BasicProfile = new BasicProfileModel(userFB.first_name, userFB.last_name) { Gender = (userFB.gender == "male" ? 'm' : 'f'), Picture = pic, DateOfBirth = DateTime.ParseExact(userFB.birthday, @"MM/dd/yyyy", CultureInfo.InvariantCulture) },
                ExtendedProfile = new ExtendedProfileModel() { },
                Id = m.currentUser.Id
            };
            p.currentUser.Save();

            return FacebookLocalAuth(result.access_token);
        }
        private ActionResult FacebookLocalAuth(string accessToken)
        {
            CouchbaseMembershipProvider m = System.Web.Security.Membership.Provider as CouchbaseMembershipProvider;
            CustomPrincipalSerializeModel serializeModel = new CustomPrincipalSerializeModel()
            {
                Email = m.currentUser.Email,
                Name = m.currentUser.UserName,
                ExternalProvider = "facebook",
                AccessToken = accessToken
            };

            FormsAuthenticationTicket authTicket = new FormsAuthenticationTicket(1, m.currentUser.UserName, DateTime.Now,
                DateTime.Now.AddMinutes(FormsAuthentication.Timeout.TotalMinutes), false, JsonConvert.SerializeObject(serializeModel));
            HttpCookie faCookie = new HttpCookie(FormsAuthentication.FormsCookieName,
                FormsAuthentication.Encrypt(authTicket));
            Response.Cookies.Add(faCookie);

            return Json(new { redirect = true, url = Url.Action("Index", "Main") }, JsonRequestBehavior.DenyGet);
        }

        //
        // GET: /Account/ForgotPassword

        [HttpGet]
        [AllowAnonymous]
        public ActionResult ForgotPassword()
        {
            return View();
        }

        //
        // POST: /Account/ForgotPassword

        [HttpPost]
        [AllowAnonymous]
        public ActionResult ForgotPassword(int step = -1, string email = "", int code = 0, string answer = "")
        {
            switch (step)
            {
                case 0:
                    {
                        var result = MvcApplication.CouchbaseClient.ExecuteGet<string>(email);
                        if (result.HasValue)
                        {
                            ConfirmationCode(email);
                            UserMembership data = JsonConvert.DeserializeObject<UserMembership>(result.Value);
                            return Json(new { status = "success", username = data.UserName }, JsonRequestBehavior.AllowGet);
                        }

                        return Json(new { status = "fail", reason = result.Message }, JsonRequestBehavior.AllowGet);
                    }
                case 1:
                    {
                        var result_code = MvcApplication.CouchbaseClient.ExecuteGet<int>(email + "_passwordResetToken");
                        if (result_code.HasValue)
                        {
                            if (result_code.Value == code)
                            {
                                var result_profile = MvcApplication.CouchbaseClient.ExecuteGet<string>(email);
                                if (result_profile.HasValue)
                                {
                                    UserMembership data = JsonConvert.DeserializeObject<UserMembership>(result_profile.Value);
                                    return Json(new { status = "success", securityQuestion = data.PasswordQuestion }, JsonRequestBehavior.AllowGet);
                                }

                                return Json(new { status = "fail", reason = result_profile.Message }, JsonRequestBehavior.AllowGet);
                            }
                        }

                        return Json(new { status = "fail", reason = result_code.Message }, JsonRequestBehavior.AllowGet);
                    }
                case 2:
                    {
                        var result = MvcApplication.CouchbaseClient.ExecuteGet<string>(email);
                        if (result.HasValue)
                        {
                            UserMembership data = JsonConvert.DeserializeObject<UserMembership>(result.Value);
                            try
                            {
                                CouchbaseMembershipProvider p = (CouchbaseMembershipProvider)System.Web.Security.Membership.Provider;
                                p.ResetPassword(email, answer);

                                return Json(new { status = "success" }, JsonRequestBehavior.AllowGet);
                            }
                            catch (Exception e)
                            {
                                return Json(new { status = "fail", reason = e.ToString() }, JsonRequestBehavior.AllowGet);
                            }
                        }

                        return Json(new { status = "fail", reason = result.Message }, JsonRequestBehavior.AllowGet);
                    }
                default:
                    {
                        return Json(new { status = "fail", reason = "No step provided" }, JsonRequestBehavior.AllowGet);
                    }
            }            
        }
        private void ConfirmationCode(string email)
        {
            Random rand = new Random();
            int number = 0;

            for (int i = 0; i < 8; i++)
                number = number * 10 + rand.Next(10);


            var result = MvcApplication.CouchbaseClient.ExecuteStore(Enyim.Caching.Memcached.StoreMode.Set,
                email + "_passwordResetToken", number, DateTime.UtcNow.AddMinutes(15));

            if (result.Success)
            {
                MailMessage msg = new MailMessage("schedule_organiser@localhost.com", email, "Password Reset Token", number.ToString() + " " + "http://localhost:21843/Account/ForgotPassword#email=" + email + "/token=" + number + "/");
                SmtpClient SMTPServer = new SmtpClient("smtp.live.com", 587) { Credentials = new NetworkCredential("tony.hegyes@hotmail.com", "~MgXqzA$"), DeliveryMethod = SmtpDeliveryMethod.Network, EnableSsl = true };

                try
                {
                    Task sendMail = new Task(new Action(delegate() { SMTPServer.Send(msg); }));
                    sendMail.Start();
                }
                catch (Exception e)
                {
                    throw e;
                }
            }
        }

        //
        // POST: /Account/LogOff

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            FormsAuthentication.SignOut();
            Session.Abandon(); Response.Clear();

            return RedirectToAction("Index", "Home");
        }

        //
        // GET: /Account/Register

        [AllowAnonymous]
        public ActionResult Register()
        {
            ViewBag.availableSecurityQuestions = JsonConvert.SerializeObject(from DataRow x in MvcApplication.LanguageAgent.LanguageDataSet.Tables["Account"].Select()
                                                                             where (x[0] as string).Contains("SecurityQuestion")
                                                                             select (x[1] as string), Formatting.Indented);
            return View();
        }

        //
        // POST: /Account/Register

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Register(RegisterModel model)
        {
            if (!model.AgreeToTerms_Conditions)
            {
                ModelState.AddModelError(String.Empty, MvcApplication.GetDisplayNameFor("termsNotAgreed_error", "Account"));
                return View(model);
            }
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError(String.Empty, MvcApplication.GetDisplayNameFor("registrationModel_error", "Account"));
                return View(model);
            }

            CouchbaseMembershipProvider m = System.Web.Security.Membership.Provider as CouchbaseMembershipProvider;
            MembershipCreateStatus s = new MembershipCreateStatus();

            string guid = Guid.NewGuid().ToString();
            m.currentUser = m.CreateUser(model.FirstName + " " + model.LastName, model.Password, model.Email, 
                model.PasswordQuestion, model.PasswordAnswer, true, guid, out s) as UserMembership;

            if (s != MembershipCreateStatus.Success)
            {
                ModelState.AddModelError(String.Empty, ErrorCodeToString(s));
                return View(model);
            }

            CouchbaseProfileProvider p = Profile.Providers["CouchbaseProfileProvider"] as CouchbaseProfileProvider;
            p.currentUser = new UserProfile()
            {
                BasicProfile = new BasicProfileModel(model.FirstName, model.LastName) 
                { 
                    DateOfBirth = new DateTime(model.Year, (DateTimeFormatInfo.CurrentInfo.AbbreviatedMonthNames).ToList().FindIndex(w => w.Trim('.') == model.Month) + 1, model.Day),
                    Gender = model.Sex
                },                    
                ExtendedProfile = new ExtendedProfileModel() 
                {
                },
                Id = guid
            };

            return Login(new LoginModel() { Email = model.Email, Password = model.Password, RememberMe = true });
        }

        #region Helpers
           private static string ErrorCodeToString(MembershipCreateStatus createStatus)
            {
                switch (createStatus)
                {
                    case MembershipCreateStatus.DuplicateUserName:
                        return "User name already exists. Please enter a different user name.";
                  
                    case MembershipCreateStatus.DuplicateEmail:
                        return "A user name for that e-mail address already exists. Please enter a different e-mail address.";

                    case MembershipCreateStatus.InvalidPassword:
                        return "The password provided is invalid. Please enter a valid password value.";

                    case MembershipCreateStatus.InvalidEmail:
                        return "The e-mail address provided is invalid. Please check the value and try again.";

                    case MembershipCreateStatus.InvalidAnswer:
                        return "The password retrieval answer provided is invalid. Please check the value and try again.";

                    case MembershipCreateStatus.InvalidQuestion:
                        return "The password retrieval question provided is invalid. Please check the value and try again.";

                    case MembershipCreateStatus.InvalidUserName:
                        return "The user name provided is invalid. Please check the value and try again.";

                    case MembershipCreateStatus.ProviderError:
                        return "The authentication provider returned an error. Please verify your entry and try again. If the problem persists, please contact your system administrator.";

                    case MembershipCreateStatus.UserRejected:
                        return "The user creation request has been canceled. Please verify your entry and try again. If the problem persists, please contact your system administrator.";

                    default:
                        return "An unknown error occurred. Please verify your entry and try again. If the problem persists, please contact your system administrator.";
                }
            }
        #endregion
    }
}
