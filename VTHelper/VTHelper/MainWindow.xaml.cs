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

        private async void ParseDomainReportAsync(string domain)
        {
            DomainReport domainReport = await App.ScanDomainAsync(domain);
        }

        private async void ParseFileReportAsync(string filePath)
        {
            FileReport fileReport = await App.ScanFileAsync(filePath);
        }

        private async void ParseIPReportAsync(string ip)
        {
            IPReport iPReport = await App.IPReportAsync(ip);
        }

        private void GetDomainReportBtn_Click(object sender, RoutedEventArgs e)
        {
            ParseDomainReportAsync(DomainName_TextBox.Text);
        }

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

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            ScanFile_Panel.Visibility = Visibility.Hidden;
            ScanDomain_Panel.Visibility = Visibility.Visible;
        }

        private void Button_Click_1(object sender, RoutedEventArgs e)
        {
            ScanFile_Panel.Visibility = Visibility.Visible;
            ScanDomain_Panel.Visibility = Visibility.Hidden;
        }
    }
}
