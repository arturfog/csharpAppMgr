using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Windows;
using VirusTotalNET;
using VirusTotalNET.Results;

namespace VTHelper
{
    /// <summary>
    /// Logika interakcji dla klasy App.xaml
    /// </summary>
    public partial class App : Application
    {        
        public static string GetAPIKey()
        {
            // Open the file to read from.
            using (StreamReader sr = File.OpenText("API.txt"))
            {
                string s = sr.ReadLine();
                return s;
            }
        }
        /// <summary>
        /// 
        /// </summary>
        public static async System.Threading.Tasks.Task ScanDomainAsync(string domain)
        {
            VirusTotal vt = new VirusTotal(App.GetAPIKey());
            DomainReport domainReport = await vt.GetDomainReportAsync(domain);
        }
    }
}
