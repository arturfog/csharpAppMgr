using Microsoft.Win32;
using System;
using System.IO;
using System.Windows;
using VirusTotalNET.Results;

namespace VTHelper
{
    /// <summary>
    /// Logika interakcji dla klasy MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="domain"></param>
        private async void ParseDomainReportAsync(string domain)
        {
            DomainReport domainReport = await App.GetDomainReportAsync(domain);
            
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
        /// <param name="filePath"></param>
        private async void ParseFileReportAsync(string filePath)
        {
            ScanResult scanResult = await App.ScanFileAsync(filePath);
            //scanResult.MD5;
            //scanResult.SHA256;
            //scanResult.Permalink;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="ip"></param>
        private async void ParseIPReportAsync(string ip)
        {
            IPReport ipReport = await App.GetIPReportAsync(ip);
            IPCountry_Lbl.Content = ipReport.Country;
            IPOwner_Lbl.Content = ipReport.AsOwner;
            //ipReport.DetectedUrls[0].Total;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void GetDomainReportBtn_Click(object sender, RoutedEventArgs e)
        {
            ParseDomainReportAsync(DomainName_TextBox.Text);
        }

        private void ScanDomainBtn_Click(object sender, RoutedEventArgs e)
        {
            ScanDomainAsync(DomainName_TextBox.Text);
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

        private void ScanFileBtn_Click(object sender, RoutedEventArgs e)
        {
            ParseFileReportAsync(FileName_TextBox.Text);
        }

        private void GetIPReportBtn_Click(object sender, RoutedEventArgs e)
        {
            ParseIPReportAsync(IP_TextBox.Text);
        }
    }
}
