using System.Text;
using System.Windows;
using System.IO;

namespace CW___Blowfish
{
    /// <summary>
    /// Логика взаимодействия для Instructions.xaml
    /// </summary>
    public partial class Instructions : Window
    {
        public Instructions()
        {
            InitializeComponent();
            StreamReader sr = new StreamReader("Help.txt", Encoding.GetEncoding(1251));
            Help.Text = sr.ReadToEnd();
        }
    }
}
