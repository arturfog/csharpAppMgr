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
            DomainReport domainReport = await App.ScanDomainAsync(domain);
            BitDefenderDomainCat_Lbl.Content = domainReport.BitDefenderCategory;
            ForcePointDomainCat_Lbl.Content = domainReport.ForcePointThreatSeekerCategory;
            WHOIS_Lbl.Text = domainReport.WhoIs;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="filePath"></param>
        private async void ParseFileReportAsync(string filePath)
        {
            FileReport fileReport = await App.ScanFileAsync(filePath);
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="ip"></param>
        private async void ParseIPReportAsync(string ip)
        {
            IPReport iPReport = await App.IPReportAsync(ip);
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
        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void GetFileReportBtn_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog1 = new OpenFileDialog();

            Nullable<bool> result = openFileDialog1.ShowDialog();
            if (result == true)
            {
                FileInfo fileInfo = new FileInfo(openFileDialog1.FileName);
                string sha256 = VirusTotalNET.Helpers.HashHelper.GetSHA256(fileInfo);
                FileName_TextBox.Text = fileInfo.FullName;
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void ScanFileTabBtn_Click(object sender, RoutedEventArgs e)
        {
            ScanFile_Panel.Visibility = Visibility.Visible;
            ScanDomain_Panel.Visibility = Visibility.Hidden;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void ScanDomainTabBtn_Click(object sender, RoutedEventArgs e)
        {
            ScanFile_Panel.Visibility = Visibility.Hidden;
            ScanDomain_Panel.Visibility = Visibility.Visible;
        }
        
        private void Button_Click(object sender, RoutedEventArgs e)
        {
            ParseFileReportAsync(FileName_TextBox.Text);
        }
    }
}
