using System.Web.Mvc;
using Newtonsoft.Json;
using System.Threading;

using schedule_organiser.Providers.Account;
namespace schedule_organiser.Controllers
{
    public class HomeController : Controller
    {
        //
        // GET: /Home/

        public ActionResult Index()
        {
            int i;
            CouchbaseMembershipProvider p = System.Web.Security.Membership.Provider as CouchbaseMembershipProvider;
            p.GetAllUsers(10, 10, out i);

            MvcApplication.LanguageAgent.ChangeLanguage(Thread.CurrentThread.CurrentUICulture.TwoLetterISOLanguageName);
            ViewBag.currentCulture = Thread.CurrentThread.CurrentUICulture.TwoLetterISOLanguageName;
            return View();
        }

        //
        // POST: /Home/LanguageChange

        [HttpPost]
        public ActionResult LanguageChange(string newLanguage)
        {
            MvcApplication.LanguageAgent.ChangeLanguage(newLanguage);

            return Json(new { LanguageDataSetHome = JsonConvert.SerializeObject(MvcApplication.LanguageAgent.LanguageDataSet.Tables["Home"], Formatting.Indented), 
                LanguageDataSetAccount = JsonConvert.SerializeObject(MvcApplication.LanguageAgent.LanguageDataSet.Tables["Account"], Formatting.Indented) }, 
                JsonRequestBehavior.DenyGet);
        }
    }
}
