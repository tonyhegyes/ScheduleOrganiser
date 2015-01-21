using System;
using System.Web;
using System.Linq;
using System.Data;
using System.Reflection;
using System.Data.SqlServerCe;
using System.Collections.Generic;

namespace schedule_organiser.Providers
{
    public sealed class DisplayLanguageProvider : IDisposable
    {
        public DataSet LanguageDataSet = new DataSet();
        public List<string> LanguageComboBoxItems = new List<string>();

        public DisplayLanguageProvider()
        {
            IEnumerable<string> availableLanguages_names = from string language in Assembly.GetExecutingAssembly().GetManifestResourceNames()
                                                           where language.Contains(".GIF")
                                                           select language;

            foreach (string languageFlag in availableLanguages_names)
                LanguageComboBoxItems.Add(languageFlag.Substring(languageFlag.Remove(languageFlag.LastIndexOf('.')).LastIndexOf('.') + 1, 2));
        }

        public void ChangeLanguage(string newLanguage)
        {
            LanguageDataSet.Tables.Clear();
            SqlCeConnection con = new SqlCeConnection("Data Source=" + HttpContext.Current.Server.MapPath("~/Content") + "\\languages\\" + newLanguage + ".sdf;");
            con.Open();
            SqlCeDataReader tableReader = new SqlCeCommand("SELECT table_name FROM INFORMATION_SCHEMA.Tables", con).ExecuteReader();
            while (tableReader.Read())
                new SqlCeDataAdapter(String.Format("SELECT * FROM {0}", tableReader[0]), con).Fill(LanguageDataSet, tableReader[0] as string);
            tableReader.Close();
            con.Close();
        }

        public void Dispose() { LanguageDataSet.Dispose(); }
    }
}