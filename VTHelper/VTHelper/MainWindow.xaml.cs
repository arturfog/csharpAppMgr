using Microsoft.Win32;
using System;
using System.IO;
using System.Windows;
using VirusTotalNET.Results;
using System.Collections.Generic;

namespace VTHelper
{
    /// <summary>
    /// Logika interakcji dla klasy MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private DomainReport domainReport;
        private IPReport ipReport;
        private UrlReport urlReport;
        private FileReport fileReport;

        public MainWindow()
        {
            InitializeComponent();
        }
        const string urlScanLinkStart = "https://www.virustotal.com/#/url/";
        const string fileScanLinkStart = "https://www.virustotal.com/#/file/";
        const string urlScanLinkEnd = "/detection";
        /// <summary>
        /// 
        /// </summary>
        /// <param name="domain"></param>
        private async void ParseDomainReportAsync(string domain)
        {
            domainReport = await App.GetDomainReportAsync(domain);
            
            ForcePointDomainCat_Lbl.Content = domainReport.ForcePointThreatSeekerCategory;
            AlexaDomainInfo_Lbl.Content = domainReport.AlexaDomainInfo;
            WHOIS_Lbl.Text = domainReport.WhoIs;
            string subdomains = String.Join("\n", domainReport.SubDomains.ToArray());
            Subdomains_Lbl.Content = subdomains;
            WebutationDomainInfo_Lbl.Content = domainReport.WebutationDomainInfo.Verdict + "[Score: " + domainReport.WebutationDomainInfo.SafetyScore + "]";

            if(domainReport.WebutationDomainInfo.SafetyScore > 50)
            {
                // safe
            }

            if(domainReport.DetectedUrls.Count > 0)
            {
                DomainReportURLDetectedPositives_Lbl.Content = domainReport.DetectedUrls[0].Positives;
                DomainReportURLDetectedTotalEngines_Lbl.Content = domainReport.DetectedUrls[0].Total;
                DomainReportURLDetectedDate_Lbl.Content = domainReport.DetectedUrls[0].ScanDate;
            }
            if(domainReport.DetectedDownloadedSamples.Count > 0)
            {
                DomainReportDownloadSamplesPosisives_Lbl.Content = domainReport.DetectedDownloadedSamples[0].Positives;
                DomainReportDownloadSamplesTotal_Lbl.Content = domainReport.DetectedDownloadedSamples[0].Total;
                DomainReportDownloadSamplesDate_Lbl.Content = domainReport.DetectedDownloadedSamples[0].Date;
            }
            if(domainReport.UndetectedUrls.Count > 0)
            {
                DomainReportURLUndetectedPositives_Lbl.Content = domainReport.UndetectedUrls[0][2];
                DomainReportURLUndetectedTotalEngines_Lbl.Content = domainReport.UndetectedUrls[0][3];
                DomainReportURLUndetectedDate_Lbl.Content = domainReport.UndetectedUrls[0][4];
            }
            if(domainReport.UndetectedDownloadedSamples.Count > 0)
            {
                DomainReportUndetectedDownloadSamplesPosisives_Lbl.Content = domainReport.UndetectedDownloadedSamples[0].Positives;
                DomainReportUndetectedDownloadSamplesTotal_Lbl.Content = domainReport.UndetectedDownloadedSamples[0].Total;
                DomainReportUndetectedDownloadSamplesDate_Lbl.Content = domainReport.UndetectedDownloadedSamples[0].Date;                
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="domain"></param>
        private async void ScanDomainAsync(string domain)
        {
            UrlScanResult scanResult = await App.ScanDomainAsync(domain);
            DomainScanPermlink_Lbl.Content = scanResult.Permalink;
            if(scanResult.ResponseCode.ToString() == "Queued")
            {

            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="url"></param>
        private async void ScanURLAsync(string url)
        {
            UrlReport urlReport = await App.GetUrlReportAsync(url);
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="url"></param>
        private async void ParseURLReportAsync(string url)
        {
            urlReport = await App.GetUrlReportAsync(url);

            URLReportURLDetectedPositives_Lbl.Content = urlReport.Positives;
            URLReportURLDetectedTotalEngines_Lbl.Content = urlReport.Total;
            URLReportURLDetectedDate_Lbl.Content = urlReport.ScanDate;

            foreach (var item in urlReport.Scans)
            {
                if (item.Value.Detected)
                {
                    FileReportAV0Name_Lbl.Content = item.Key;
                    FileReportAV0VirusName_Lbl.Content = item.Value.Result;
                }
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="filePath"></param>
        private async void ScanFileAsync(string filePath)
        {
            ScanResult scanResult = await App.ScanFileAsync(filePath);
            FileReportMD5_Lbl.Content = scanResult.MD5;
            FileReportSHA256_Lbl.Content = scanResult.SHA256;
            FileReportSHA1_Lbl.Content = scanResult.SHA1;
            FileScanPermlink_Lbl.Content = scanResult.Permalink;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="filePath"></param>
        private async void ParseFileReportAsync(string filePath)
        {
            fileReport = await App.GetFileReportAsync(filePath);
            FileReportMD5_Lbl.Content = fileReport.MD5;
            FileReportSHA256_Lbl.Content = fileReport.SHA256;
            FileReportSHA1_Lbl.Content = fileReport.SHA1;

            FileReportDate_Lbl.Content = fileReport.ScanDate;
            FileReportPositives_Lbl.Content = fileReport.Positives;
            FileReportTotalEngines_Lbl.Content = fileReport.Total;
            foreach(var item in fileReport.Scans)
            {
                if(item.Value.Detected)
                {
                    FileReportAV0Name_Lbl.Content = item.Key;
                    FileReportAV0VirusName_Lbl.Content = item.Value.Result;
                    FileReportAV0Update_Lbl.Content = item.Value.Update;
                    FileReportAV0Version_Lbl.Content = item.Value.Version;
                }
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="ip"></param>
        private async void ParseIPReportAsync(string ip)
        {
            ipReport = await App.GetIPReportAsync(ip);
            IPCountry_Lbl.Content = ipReport.Country;
            IPOwner_Lbl.Content = ipReport.AsOwner;

            if (ipReport.DetectedUrls.Count > 0)
            {
                IPReportURLDetectedPositives_Lbl.Content = ipReport.DetectedUrls[0].Positives;
                IPReportURLDetectedTotalEngines_Lbl.Content = ipReport.DetectedUrls[0].Total;
                IPReportURLDetectedDate_Lbl.Content = ipReport.DetectedUrls[0].ScanDate;
            }

            if (ipReport.DetectedDownloadedSamples.Count > 0)
            {
                IPReportDownloadSamplesPosisives_Lbl.Content = ipReport.DetectedDownloadedSamples[0].Positives;
                IPReportDownloadSamplesTotal_Lbl.Content = ipReport.DetectedDownloadedSamples[0].Total;
                IPReportDownloadSamplesDate_Lbl.Content = ipReport.DetectedDownloadedSamples[0].Date;
            }

            if (ipReport.UndetectedDownloadedSamples.Count > 0)
            {
                IPReportUndetectedDownloadSamplesTotal_Lbl.Content = ipReport.UndetectedDownloadedSamples[0].Total;
                IPReportUndetectedDownloadSamplesPosisives_Lbl.Content = ipReport.UndetectedDownloadedSamples[0].Positives;
                IPReportUndetectedDownloadSamplesDate_Lbl.Content = ipReport.UndetectedDownloadedSamples[0].Date;
            }

            if (ipReport.UndetectedUrls.Count > 0)
            {
                IPReportURLUndetectedPositives_Lbl.Content = ipReport.UndetectedUrls[0][2];
                IPReportURLUndetectedTotalEngines_Lbl.Content = ipReport.UndetectedUrls[0][3];
                IPReportURLUndetectedDate_Lbl.Content = ipReport.UndetectedUrls[0][4];
            }
        }
        
        private void GetDomainReportBtn_Click(object sender, RoutedEventArgs e)
        {
            ParseDomainReportAsync(DomainName_TextBox.Text);
        }
        
        private void ScanDomainBtn_Click(object sender, RoutedEventArgs e)
        {
            ScanDomainAsync(DomainName_TextBox.Text);
        }

        private void GetURLReportBtn_Click(object sender, RoutedEventArgs e)
        {
            ParseURLReportAsync(URL_TextBox.Text);
        }

        private void ScanURLBtn_Click(object sender, RoutedEventArgs e)
        {
            ScanURLAsync(URL_TextBox.Text);
        }

        private void ScanFileBtn_Click(object sender, RoutedEventArgs e)
        {
            ScanFileAsync(FileName_TextBox.Text);
        }

        private void GetFileReportBtn_Click(object sender, RoutedEventArgs e)
        {
            ParseFileReportAsync(FileName_TextBox.Text);
        }

        private void GetIPReportBtn_Click(object sender, RoutedEventArgs e)
        {
            ParseIPReportAsync(IP_TextBox.Text);
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void SelectFileBtn_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();

            Nullable<bool> result = openFileDialog.ShowDialog();
            if (result == true)
            {
                FileInfo fileInfo = new FileInfo(openFileDialog.FileName);
                string sha256 = VirusTotalNET.Helpers.HashHelper.GetSHA256(fileInfo);
                FileName_TextBox.Text = fileInfo.FullName;
            }
        }


        private void showTab(System.Windows.Controls.StackPanel panel)
        {
            ScanFile_Panel.Visibility = Visibility.Hidden;
            ScanDomain_Panel.Visibility = Visibility.Hidden;
            Settings_Panel.Visibility = Visibility.Hidden;
            About_Panel.Visibility = Visibility.Hidden;
            ScanIP_Panel.Visibility = Visibility.Hidden;
            ScanURL_Panel.Visibility = Visibility.Hidden;

            panel.Visibility = Visibility.Visible;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void ScanFileTabBtn_Click(object sender, RoutedEventArgs e)
        {
            showTab(ScanFile_Panel);
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void ScanDomainTabBtn_Click(object sender, RoutedEventArgs e)
        {
            showTab(ScanDomain_Panel);
        }

        private void ScanURLTabBtn_Click(object sender, RoutedEventArgs e)
        {
            showTab(ScanURL_Panel);
        }

        private void SettingsTabBtn_Click(object sender, RoutedEventArgs e)
        {
            showTab(Settings_Panel);
        }

        private void AboutTabBtn_Click(object sender, RoutedEventArgs e)
        {
            showTab(About_Panel);
        }

        private void ScanIPTabBtn_Click(object sender, RoutedEventArgs e)
        {
            showTab(ScanIP_Panel);
        }

        private void DomainReportURLDetectedLink_Click(object sender, RoutedEventArgs e)
        {
            System.Diagnostics.Process.Start(domainReport.DetectedUrls[0].Url);
        }

        private void DomainReportDownloadSamplesLink_Click(object sender, RoutedEventArgs e)
        {
            if (domainReport.DetectedDownloadedSamples.Count > 0)
            {
                string hash = domainReport.DetectedDownloadedSamples[0].Sha256;
                string link = String.Concat(fileScanLinkStart, hash, urlScanLinkEnd);

                System.Diagnostics.Process.Start(link);
            }
        }

        private void DomainReportURLUndetectedLink_Click(object sender, RoutedEventArgs e)
        {
            string hash = domainReport.UndetectedUrls[0][1];
            string link = String.Concat(urlScanLinkStart, hash, urlScanLinkEnd);

            System.Diagnostics.Process.Start(link);
        }

        private void DomainReportUndetectedDownloadSamplesLink_Click(object sender, RoutedEventArgs e)
        {
            string hash = domainReport.UndetectedDownloadedSamples[0].Sha256;
            string link = String.Concat(fileScanLinkStart, hash, urlScanLinkEnd);

            System.Diagnostics.Process.Start(link);
        }

        private void IPReportDownloadSamplesLink_Click(object sender, RoutedEventArgs e)
        {
            string hash = ipReport.DetectedDownloadedSamples[0].Sha256;
            string link = String.Concat(fileScanLinkStart, hash, urlScanLinkEnd);

            System.Diagnostics.Process.Start(link);
        }

        private void IPReportURLUndetectedLink_Click(object sender, RoutedEventArgs e)
        {
            string hash = ipReport.UndetectedUrls[0][1];
            string link = String.Concat(urlScanLinkStart, hash, urlScanLinkEnd);

            System.Diagnostics.Process.Start(link);
        }

        private void IPReportUndetectedDownloadSamplesLink_Click(object sender, RoutedEventArgs e)
        {
            string hash = ipReport.UndetectedDownloadedSamples[0].Sha256;
            string link = String.Concat(fileScanLinkStart, hash, urlScanLinkEnd);

            System.Diagnostics.Process.Start(link);
        }

        private void FileReportLink_Click(object sender, RoutedEventArgs e)
        {
            string hash = fileReport.SHA256;
            string link = String.Concat(fileScanLinkStart, hash, urlScanLinkEnd);

            System.Diagnostics.Process.Start(link);
        }
    }
}
