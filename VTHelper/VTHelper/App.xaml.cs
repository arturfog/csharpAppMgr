using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Windows;
using VirusTotalNET;
using VirusTotalNET.Results;
using System.Threading.Tasks;

namespace VTHelper
{
    /// <summary>
    /// Logika interakcji dla klasy App.xaml
    /// </summary>
    public partial class App : Application
    {
        static VirusTotal vt = new VirusTotal(GetAPIKey());

        public static VirusTotal Vt { get => vt; set => vt = value; }

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
        public static async Task<DomainReport> ScanDomainAsync(string domain)
        {   
            DomainReport domainReport = await Vt.GetDomainReportAsync(domain);
            return domainReport;
        }

        public static async Task<FileReport> ScanFileAsync(string file)
        {
            FileInfo fileInfo = new FileInfo(file);
            FileReport fileReport = await Vt.GetFileReportAsync(fileInfo);
            return fileReport;
        }

        public static async Task<IPReport> IPReportAsync(string ip)
        {
            IPReport iPReport = await Vt.GetIPReportAsync(ip);
            return iPReport;
        }
    }
}
