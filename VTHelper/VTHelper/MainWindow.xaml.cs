using Microsoft.Win32;
using System;
using System.IO;
using System.Windows;
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

        private void Button_Click_4(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog1 = new OpenFileDialog();

            Nullable<bool> result = openFileDialog1.ShowDialog();
            if (result == true)
            {
                FileInfo fileInfo = new FileInfo(openFileDialog1.FileName);
                string sha256 = VirusTotalNET.Helpers.HashHelper.GetSHA256(fileInfo);

                App.ScanDomainAsync("google.pl");
            }
        }
    }
}
