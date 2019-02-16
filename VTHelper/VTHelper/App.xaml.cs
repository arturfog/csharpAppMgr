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
        public static async Task<UrlScanResult> ScanDomainAsync(string domain)
        {
            UrlScanResult urlScanResult = await Vt.ScanUrlAsync(domain);
            return urlScanResult;
        }

        public static async Task<DomainReport> GetDomainReportAsync(string domain)
        {
            DomainReport domainReport = await Vt.GetDomainReportAsync(domain);
            return domainReport;
        }

        public static async Task<UrlReport> GetUrlReportAsync(string url)
        {
            UrlReport urlReport = await Vt.GetUrlReportAsync(url);
            return urlReport;
        }


        public static async Task<FileReport> GetFileReportAsync(string file)
        {
            FileInfo fileInfo = new FileInfo(file);
            FileReport fileReport = await Vt.GetFileReportAsync(fileInfo);
            return fileReport;
        }

        public static async Task<ScanResult> ScanFileAsync(string file)
        {
            FileInfo fileInfo = new FileInfo(file);
            ScanResult scanResult = await Vt.ScanFileAsync(fileInfo);
            return scanResult;
        }

        public static async Task<IPReport> GetIPReportAsync(string ip)
        {
            IPReport iPReport = await Vt.GetIPReportAsync(ip);
            return iPReport;
        }
    }
}
