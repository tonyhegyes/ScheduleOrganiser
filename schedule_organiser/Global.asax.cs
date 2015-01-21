using System;
using Couchbase;
using System.Web;
using System.Linq;
using System.Web.Mvc;
using System.Web.Http;
using Newtonsoft.Json;
using System.Reflection;
using System.Web.Routing;
using System.Web.Security;
using System.Web.Optimization;
using System.Collections.Generic;
using schedule_organiser.Providers;
using CouchbaseModelViews.Framework;
using schedule_organiser.Providers.Account;


namespace schedule_organiser
{
    public class MvcApplication : HttpApplication
    {
        public static CouchbaseClient CouchbaseClient = new CouchbaseClient("couchbase");
        public static DisplayLanguageProvider LanguageAgent = new DisplayLanguageProvider();
        public static Security SecurityAgent = new Security();

        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();

            WebApiConfig.Register(GlobalConfiguration.Configuration);
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);

            RegisterModelViews(new Assembly[] { Assembly.GetExecutingAssembly() });
        }

        protected void Session_Start(object sender, EventArgs e) 
        { 
            Session["Test"] = DateTime.Now;
        }

        //Reading cookie and replacing HttpContext.User object
        protected void Application_PostAuthenticateRequest(object sender, EventArgs e)
        {
            HttpCookie authCookie = Request.Cookies[FormsAuthentication.FormsCookieName];

            if (authCookie != null)
            {
                FormsAuthenticationTicket authTicket = FormsAuthentication.Decrypt(authCookie.Value);

                CustomPrincipalSerializeModel serializeModel = JsonConvert.DeserializeObject<CustomPrincipalSerializeModel>(authTicket.UserData);

                CustomPrincipal newUser = new CustomPrincipal(new CustomIdentity(serializeModel.Email));

                HttpContext.Current.User = newUser;
            }
        }

        public static string GetDisplayNameFor(string elementName, string tableName)
        {
            return LanguageAgent.LanguageDataSet.Tables[tableName].Select("Element_name = '" + elementName + "'")[0][1] as string;
        }

        public static void RegisterModelViews(IEnumerable<Assembly> assemblies)
        {
            var builder = new ViewBuilder();
            builder.AddAssemblies(assemblies.ToList());
            var designDocs = builder.Build();
            var ddManager = new DesignDocManager();
            ddManager.Create(designDocs);
        }

        protected void Application_End()
        {
            CouchbaseClient.Dispose();
            LanguageAgent.Dispose();
        }
    }
}