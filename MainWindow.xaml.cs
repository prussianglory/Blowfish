using Microsoft.Win32;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using winForms = System.Windows.Forms;

namespace CW___Blowfish
{


    class Blowfish
    {
        #region Глобальные константы и переменные       

        //криптографический генератор случайных чисел для задания вектора инициализации
        RNGCryptoServiceProvider InitVectorGenerator;
        //Ключ
        private byte[] Key;

        //S- и P-блоки
        private uint[] S0;
        private uint[] S1;
        private uint[] S2;
        private uint[] S3;

        private uint[] P;

        //Полублоки по 32 бита
        private uint LBlock;
        private uint RBlock;

        //Вектор инициализации для режимов CTR и CBC
        private byte[] InitVector;
        private bool InitVectorSet;

        uint Rounds = 16; // количество раундов в сети Фейстеля
        int CountP = 18; //количество P-блоков
        int CountS = 256; //количество S-блоков

        #endregion

        public Blowfish(string hexKey)
        {
            InitVectorGenerator = new RNGCryptoServiceProvider();
            SetupKey(HexToByte(hexKey));
        }      

        #region Режимы шифрования
        

        //дешифрует байтовый массив в CBC режиме
        public byte[] DecryptByCBC(byte[] ct)
        {
            return CryptByCBC(ct, true);
        }

        //шифрует байтовый массив в CBC режиме
        public byte[] EncryptByCBC(byte[] pt)
        {
            return CryptByCBC(pt, false);
        }      
        

        //шифрует байтовый массив в ECB режиме
        public byte[] EncryptByECB(byte[] pt)
        {
            return ECB(pt, false);
        }

        //дешифрует байтовый массив в ECB режиме
        public byte[] DecryptByECB(byte[] ct)
        {
            return ECB(ct, true);
        }       
              
        

        //Вектор инициализации для режима CBC
        public byte[] IV
        {
            get { return InitVector; }
            set
            {
                if (value.Length == 8)
                {
                    InitVector = value;
                    InitVectorSet = true;
                }
                else
                {
                    throw new Exception("Неправильный размер ВИ.");
                }
            }
        }

       // задаём случайный вектор инициализации
        public byte[] SetRandomIV()
        {
            InitVector = new byte[8];
            InitVectorGenerator.GetBytes(InitVector);
            InitVectorSet = true;
            return InitVector;
        }

        #endregion

        #region Методы шифрования

        //Подготовка S- и P-блоков
        private void SetupKey(byte[] cipherKey)
        {
            P = ConstSetup.SetupP();
            S0 = ConstSetup.SetupS0();
            S1 = ConstSetup.SetupS1();
            S2 = ConstSetup.SetupS2();
            S3 = ConstSetup.SetupS3();

            Key = new byte[cipherKey.Length];// 448 бита
            
            Buffer.BlockCopy(cipherKey, 0, Key, 0, cipherKey.Length);
            int j = 0;
            for (int i = 0; i < CountP; i++)
            {
                uint d = (uint)(((Key[j % cipherKey.Length] * CountS + Key[(j + 1) % cipherKey.Length]) * CountS + Key[(j + 2) % cipherKey.Length]) * CountS + Key[(j + 3) % cipherKey.Length]);
                P[i] ^= d;
                j = (j + 4) % cipherKey.Length;
            }

            LBlock = 0;
            RBlock = 0;
            
            SetupSBox(P, CountP);
            SetupSBox(S0, CountS);
            SetupSBox(S1, CountS);
            SetupSBox(S2, CountS);
            SetupSBox(S3, CountS);
        }
        private void SetupSBox(uint[] S, int Count)
        {
            for (int i = 0; i < Count; i += 2)
            {
                EncryptionFN();
                S[i] = LBlock;
                S[i + 1] = RBlock;
            }
        }

        //работа с блоками в режиме электронной кодовой книги (Electronic Code Book)
        private byte[] ECB(byte[] text, bool IsDecrypt)
        {
            int PaddedLength = (text.Length % 8 == 0 ? text.Length : text.Length + 8 - (text.Length % 8)); //устанавливаем длину, кратную 8-ми
            byte[] PlainText = new byte[PaddedLength];
            Buffer.BlockCopy(text, 0, PlainText, 0, text.Length); //дозаполняем массив нулевыми байтами
            byte[] Block = new byte[8];
            for (int i = 0; i < PlainText.Length; i += 8)
            {
                Buffer.BlockCopy(PlainText, i, Block, 0, 8);
                if (IsDecrypt)
                {
                    ReverseFeistelNetwork(ref Block);
                }
                else
                {
                    FeistelNetwork(ref Block);
                }
                Buffer.BlockCopy(Block, 0, PlainText, i, 8);
            }
            return PlainText;
        }

        public byte[] CryptByCTR(byte[] text)
        {          
            byte[] Input = new byte[8];
            byte[] Counter = new byte[8];
            int PaddedLength = (text.Length % 8 == 0 ? text.Length : text.Length + 8 - (text.Length % 8));
            byte[] PlainText = new byte[PaddedLength];
            Buffer.BlockCopy(text, 0, PlainText, 0, text.Length);
            byte[] Block = new byte[8];
            for (int i = 0; i < PlainText.Length; i += 8)
            {
                for (int x = 0; x < 8; x++)
                {
                    Input[x] = (byte)(Counter[x] ^ InitVector[x]);
                }
                Buffer.BlockCopy(PlainText, i, Block, 0, 8);
                FeistelNetwork(ref Input);
                XorBlocks(ref Block, Input);
                Buffer.BlockCopy(Block, 0, PlainText, i, 8);
            }
            return PlainText;
        }

        //шифрует или дешифрует данные в режиме CBC
        //true, чтобы дешифровать, false, чтобы дешифровать
        private byte[] CryptByCBC(byte[] text, bool decrypt)
        {
            int PaddedLen = (text.Length % 8 == 0 ? text.Length : text.Length + 8 - (text.Length % 8));
            byte[] PlainText = new byte[PaddedLen];
            Buffer.BlockCopy(text, 0, PlainText, 0, text.Length);
            byte[] block = new byte[8];
            byte[] preblock = new byte[8];
            byte[] iv = new byte[8];
            Buffer.BlockCopy(InitVector, 0, iv, 0, 8);
            if (!decrypt) 
            {
                for (int i = 0; i < PlainText.Length; i += 8)
                {
                    Buffer.BlockCopy(PlainText, i, block, 0, 8);
                    XorBlocks(ref block, iv);
                    FeistelNetwork(ref block);
                    Buffer.BlockCopy(block, 0, iv, 0, 8);
                    Buffer.BlockCopy(block, 0, PlainText, i, 8);
                }
            }
            else
            {
                for (int i = 0; i < PlainText.Length; i += 8)
                {
                    Buffer.BlockCopy(PlainText, i, block, 0, 8);

                    Buffer.BlockCopy(block, 0, preblock, 0, 8);
                    ReverseFeistelNetwork(ref block);
                    XorBlocks(ref block, iv);
                    Buffer.BlockCopy(preblock, 0, iv, 0, 8);

                    Buffer.BlockCopy(block, 0, PlainText, i, 8);
                }
            }
            return PlainText;
        }


        private void XorBlocks(ref byte[] Block, byte[] InitVector) //выполняет xor над двумя 8-битными блоками
        {
            for (int i = 0; i < Block.Length; i++)
            {
                Block[i] ^= InitVector[i];
            }
        }

        // основные действия на 64-битным блоком
        private void FeistelNetwork(ref byte[] block)
        {
            SplitIn2Blocks32(block); //разбить на 2 32-битных блока 
            EncryptionFN(); //пропускаем 2 блока через сеть Фейстеля
            UniteIntoBlock64(ref block); //объединить 2 32-битных блока в один 64-битный
        }
        //то же, что и при шифровании, но при этом применяется обратная сеть Фейстеля 
        private void ReverseFeistelNetwork(ref byte[] block)
        {
            SplitIn2Blocks32(block);
            DecryptionFN(); //отличие от обычной СФ в том, что S- и P- блоки применяются в обратном порядке
            UniteIntoBlock64(ref block);
        }
        private void SplitIn2Blocks32(byte[] block)
        {
            byte[] block1 = new byte[4];
            byte[] block2 = new byte[4];
            Buffer.BlockCopy(block, 0, block1, 0, 4);
            Buffer.BlockCopy(block, 4, block2, 0, 4);
            //Разделяем блоки           
            RBlock = BitConverter.ToUInt32(block1, 0);
            LBlock = BitConverter.ToUInt32(block2, 0);
        }
        private void UniteIntoBlock64(ref byte[] block)
        {
            byte[] block1 = new byte[4];
            byte[] block2 = new byte[4];
            block1 = BitConverter.GetBytes(RBlock);
            block2 = BitConverter.GetBytes(LBlock);
            //Соединяем блоки
            Buffer.BlockCopy(block1, 0, block, 0, 4);
            Buffer.BlockCopy(block2, 0, block, 4, 4);
        }

       // основная часть Сети Фейстеля
        private void EncryptionFN()
        {
            LBlock ^= P[0];
            for (uint i = 0; i < Rounds; i += 2)
            {
                RBlock = F(RBlock, LBlock, i + 1);
                LBlock = F(LBlock, RBlock, i + 2);
            }
            RBlock ^= P[17];
          
            uint swap = LBlock;
            LBlock = RBlock;
            RBlock = swap;
        }

        //то же, но в обратном порядке - для дешифрования
        private void DecryptionFN()
        {
            LBlock ^= P[17];
            for (uint i = Rounds; i > 0; i -= 2)
            {
                RBlock = F(RBlock, LBlock, i);
                LBlock = F(LBlock, RBlock, i - 1);
            }
            RBlock ^= P[0];
           
            uint swap = LBlock;
            LBlock = RBlock;
            RBlock = swap;
        }

        //Функция F вычисляет раундовый ключ, который будет использован в следующем раунде
        private uint F(uint a, uint b, uint index)
        {
            uint x1 = (S0[GetByte0(b)] + S1[GetByte1(b)]) ^ S2[GetByte2(b)];
            uint x2 = x1 + S3[GetByte3(b)];
            uint x3 = x2 ^ P[index];
            return x3 ^ a;
        }

        #endregion              
       

        #region Преобразования        

       //переводит 16-ричную строку в массив байт
        public byte[] HexToByte(string hex)
        {
            byte[] r = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length - 1; i += 2)
            {
                byte a = GetHex(hex[i]);
                byte b = GetHex(hex[i + 1]);
                r[i / 2] = (byte)(a * 16 + b);
            }
            return r;
        }

        //переводит 16-ричный символ в соответствующий байт
        private byte GetHex(char x)
        {
            if (x <= '9' && x >= '0')
            {
                return (byte)(x - '0');
            }
            else if (x <= 'z' && x >= 'a')
            {
                return (byte)(x - 'a' + 10);
            }
            else if (x <= 'Z' && x >= 'A')
            {
                return (byte)(x - 'A' + 10);
            }
            return 0;
        }

        //получаем 0-й байт числа
        private byte GetByte0(uint w)
        {
            return (byte)(w / 256 / 256 / 256 % 256);
        }

        //получаем 1-й байт числа
        private byte GetByte1(uint w)
        {
            return (byte)(w / 256 / 256 % 256);
        }

        //получаем 2-й байт числа
        private byte GetByte2(uint w)
        {
            return (byte)(w / 256 % 256);
        }

        //получаем 3-й байт числа
        private byte GetByte3(uint w)
        {
            return (byte)(w % 256);
        }

        #endregion
    }

    /// <summary>
    /// Логика взаимодействия для MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        enum Modes
        {
            ECB,
            CBC,
            CTR
        }
        byte[] LoadedTextBytes;
        byte[] CryptedTextBytes;
        bool IsEncrypted;
        string LoadedFileName = "";
        string Extention;
        bool IsChanged = false;
        public MainWindow()
        {
            InitializeComponent();
        }

        Instructions HelpWindow;
        About AboutWindow;

        
        
        //открыть файл из проводника
        private void ChooseFileButton(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog();
            dlg.Filter = "All files(*.*)|*.*";

            if (dlg.ShowDialog() == true)
            {
                Extention = System.IO.Path.GetExtension(dlg.FileName);
                LoadedFileName = dlg.SafeFileName;
                LoadedTextBytes = File.ReadAllBytes(dlg.FileName);
                Key.Text = "";
                CodePhrase.Text = "";
                LoadedFilePath.Text = dlg.FileName;
                InitVectorBox.Text = "";
                if (Extention == ".enc")
                {
                    CryptMode.SelectedIndex = LoadedTextBytes[LoadedTextBytes.Length - 1];
                    Array.Resize(ref LoadedTextBytes, LoadedTextBytes.Length - 1);
                    if (CryptMode.SelectedIndex != (int)Modes.ECB)
                        ExtractIV();
                }

            }
        }
        void ExtractIV()
        {
            byte[] tmpIV = new byte[8];
            Array.Copy(LoadedTextBytes, tmpIV, tmpIV.Length);
            InitVectorBox.Text = ByteToHex(tmpIV);
            Array.Copy(LoadedTextBytes, tmpIV.Length, LoadedTextBytes, 0, LoadedTextBytes.Length-tmpIV.Length);
            Array.Resize(ref LoadedTextBytes, LoadedTextBytes.Length - tmpIV.Length);
        }
        //переводит массив байт в 16-ричную строку
        string ByteToHex(byte[] bytes)
        {
            StringBuilder s = new StringBuilder();
            foreach (byte b in bytes)
                s.Append(b.ToString("x2"));
            return s.ToString();
        }
        //зашифровать
        private void ClickEncryptButton(object sender, RoutedEventArgs e)
        {
            
            IsEncrypted = true;
            IsChanged = true;
            if (LoadedFilePath.Text == "")
            {
                MessageBox.Show("Вначале загрузите файл!");
                return;
            }

            if (Key.Text == "")
            {
                MessageBox.Show("Вначале задайте ключ!");
                return;
            }             
            
            
            Blowfish bf = new Blowfish(Key.Text);          
         

            switch(CryptMode.SelectedIndex)
            {
                case (int)Modes.ECB:
                    CryptedTextBytes = bf.EncryptByECB(LoadedTextBytes);
                    Array.Resize(ref CryptedTextBytes, CryptedTextBytes.Length + 1);
                    CryptedTextBytes[CryptedTextBytes.Length - 1] = 0;
                    break;
                case (int)Modes.CBC:
                    if (!IVCheck(bf))                                       
                    return;            
                    CryptedTextBytes = bf.EncryptByCBC(LoadedTextBytes);
                    SewVectorInCipherText(bf, (byte)Modes.CBC);
                    break;
                case (int)Modes.CTR:
                    if (!IVCheck(bf))
                        return;
                    CryptedTextBytes = bf.CryptByCTR(LoadedTextBytes);
                    SewVectorInCipherText(bf, (byte)Modes.CTR);
                    break;                  
            }
            MessageBox.Show("Файл зашифрован. Теперь сохраните файл");
            SaveFileDialog();
            
        }
        private void SewVectorInCipherText(Blowfish bf, byte Mode)
        {
            CryptedTextBytes = bf.HexToByte(InitVectorBox.Text).Concat(CryptedTextBytes).ToArray();
            Array.Resize(ref CryptedTextBytes, CryptedTextBytes.Length + 1);
            CryptedTextBytes[CryptedTextBytes.Length - 1] = Mode;
        }
        //проверяем, является ли строка 16-ричной
        private bool IsHex(string str)
        {
            for (int i = 0; i < str.Length; i++)
            {
                if ((str[i] > 'f') || (str[i] < '0') || ((str[i] > '9') && (str[i] < 'A')) || ((str[i] > 'F') && (str[i] < 'a')))
                 return false;
            }
            return true;
        }
        //проверка вектора инициализации на правильность
        private bool IVCheck(Blowfish bf)
        {          
            if (InitVectorBox.Text == "")
            {
                MessageBox.Show("Введите вектор инициализации");
                return false;
            }
            else
            {
                if (InitVectorBox.Text.Length != 16)
                {
                    MessageBox.Show("Размер вектора должен быть 8-бит (16 символов 16-ричном формате)");
                    return false;
                }
                else
                {
                    if (IsHex(InitVectorBox.Text))
                    {
                        bf.IV = bf.HexToByte(InitVectorBox.Text);                        
                    }
                    else
                    {
                        MessageBox.Show("Вектор должен быть в 16-ричном формате!");
                        return false;
                    }
                        
                }
                   
            }
            return true;
        }
        // расшифровать по кнопке
        private void ClickDecryptButton(object sender, RoutedEventArgs e)
        {
            IsEncrypted = false;
            IsChanged = true;
            if (LoadedFilePath.Text == "")
            {
                MessageBox.Show("Вначале загрузите файл!");
                return;
            }
            if (Key.Text == "")
            {
                MessageBox.Show("Введите ключ!");
                return;
            } 
            if (Path.GetExtension(LoadedFileName) != ".enc")
            {
                MessageBox.Show("Файл не является зашифрованным");
                return;
            }            
            Blowfish bf = new Blowfish(Key.Text);           
            switch (CryptMode.SelectedIndex)
            {
                case (int)Modes.ECB:
                    CryptedTextBytes = bf.DecryptByECB(LoadedTextBytes);
                    break;
                case (int)Modes.CBC:
                    bf.IV = bf.HexToByte(InitVectorBox.Text);
                    CryptedTextBytes = bf.DecryptByCBC(LoadedTextBytes);
                    break;
                case (int)Modes.CTR:
                    bf.IV = bf.HexToByte(InitVectorBox.Text);
                    CryptedTextBytes = bf.CryptByCTR(LoadedTextBytes);
                    break;
            }
            MessageBox.Show("Файл расшифрован");
            SaveFileDialog();
            
        }     
        
        //сгенерировать ключ по кнопке
        private void GenerateKeyClick(object sender, RoutedEventArgs e)
        {
            Key.Text = "";
            if (CodePhrase.Text == "")
            {
                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                byte[] KeyBytes = new byte[32]; //256-битовый ключ по умолчанию
                rng.GetBytes(KeyBytes);
                Key.Text = BitConverter.ToString(KeyBytes).Replace("-","").ToLower();
            }
            else 
            {
                byte[] CPBytes = Encoding.ASCII.GetBytes(CodePhrase.Text);
                byte[] tmpHash = new MD5CryptoServiceProvider().ComputeHash(CPBytes);
                Key.Text = ByteArrayToString(tmpHash).ToLower();
            }
        }
        private static string ByteArrayToString(byte[] arrInput)
        {
            {
                int i;
                StringBuilder sOutput = new StringBuilder(arrInput.Length);
                for (i = 0; i < arrInput.Length; i++)
                {
                    sOutput.Append(arrInput[i].ToString("X2"));
                }
                return sOutput.ToString();
            }
        }        
        //сохранить файл по кнопке
        private void SaveFileClick(object sender, RoutedEventArgs e)
        {
            if (LoadedFileName == "")
            {
                MessageBox.Show("Исходный файл не загружен. Пожалуйста, выберите файл и проведите шифрование или дешифрование");
                return;
            }
            if (!IsChanged)
            {
                MessageBox.Show("Вначале проведите шифрование или дешифрование");
                return;
            }
            using (var fbd = new winForms.FolderBrowserDialog())
            {
                winForms.DialogResult result = fbd.ShowDialog();

                if (result == winForms.DialogResult.OK && !string.IsNullOrWhiteSpace(fbd.SelectedPath))
                {
                    File.WriteAllBytes(fbd.SelectedPath + "\\" + LoadedFileName, CryptedTextBytes);
                    MessageBox.Show("Файл сохранён");
                }
            }
        }
        private void SaveFileDialog()
        {
            string PrevFileName = LoadedFileName;
            // SaveFileDialog SFD = new SaveFileDialog();

            using (var fbd = new winForms.FolderBrowserDialog())
            {
                winForms.DialogResult result = fbd.ShowDialog();

                if (result == winForms.DialogResult.OK && !string.IsNullOrWhiteSpace(fbd.SelectedPath))
                {
                    if (IsEncrypted)
                    {                        
                        LoadedFileName += ".enc";
                    }
                    else
                    {
                        string EncExtintion = ".enc";
                        int ExtIndex = LoadedFileName.IndexOf(EncExtintion);
                        LoadedFileName =LoadedFileName.Remove(ExtIndex, EncExtintion.Length);
                    }
                    File.WriteAllBytes(fbd.SelectedPath + "\\"+ LoadedFileName, CryptedTextBytes);
                    MessageBox.Show("Файл сохранён");
                    LoadedFileName = PrevFileName;
                }               
                
            }
        }
        //сгенерировать вектор инициализации по кнопке
        private void GenerateInitVectorClick(object sender, RoutedEventArgs e)
        {
            if (Key.Text == "")
            {
                MessageBox.Show("Вначале задайте ключ!");
            }
            else
            {
                Blowfish bf = new Blowfish(Key.Text);
                InitVectorBox.Text = BitConverter.ToString(bf.SetRandomIV()).Replace("-","").ToLower();
            }
        }
        // справка по пользованию программы
        private void HelpButtonClick(object sender, RoutedEventArgs e)
        {
            if (HelpWindow == null)
            {
                HelpWindow = new Instructions();
                HelpWindow.Closing += HelpWindowClosing;
                HelpWindow.Show();
            }
        }

        private void HelpWindowClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            HelpWindow = null;
        }

        private void MainWindowClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {           
            if (HelpWindow != null)
                HelpWindow.Close();
        }
        //видимость поля В.И. в зависимости 
        private void SetVectorVisibility(object sender, SelectionChangedEventArgs e)
        {            
            if (CryptMode.SelectedIndex != 0)
            {
                InitVectorLabel.Visibility = Visibility.Visible;
                InitVectorBox.Visibility = Visibility.Visible;
                GenerateInitVector.Visibility = Visibility.Visible;                
            }
            else
            {
                InitVectorLabel.Visibility = Visibility.Hidden;
                InitVectorBox.Visibility = Visibility.Hidden;
                GenerateInitVector.Visibility = Visibility.Hidden;               
            }
        }
        private void SaveKeyIntoFile(object sender, RoutedEventArgs e)
        {
            if (Key.Text == "")
            {
                MessageBox.Show("Поле ключа не должно быть пустым!");
                return;
            }
            SaveFileDialog SFD = new SaveFileDialog();

            SFD.Filter = "Key files(*.key)|*.key";

            if (SFD.ShowDialog() == true)
            {
                using (StreamWriter sw = new StreamWriter(SFD.OpenFile(), Encoding.GetEncoding(1251)))
                {
                    sw.WriteLine(Key.Text);
                    sw.Close();
                }
            }
        }

        private void OpenKeyFile(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog();
            dlg.Filter = "Key files(*.key)|*.key|All files(*.*)|*.*";

            if (dlg.ShowDialog() == true)
            {
                StreamReader KeyStream = new StreamReader(dlg.FileName);
                Key.Text = KeyStream.ReadToEnd().Replace("\r\n", "");
            }
        }

        private void AboutClick(object sender, RoutedEventArgs e)
        {
            if (AboutWindow == null)
            {
                AboutWindow = new About();
                AboutWindow.Closing += AboutClosing;
                AboutWindow.Show();
            }
        }

        private void AboutClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {
                AboutWindow = null;
        }

        private void MWClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            if (AboutWindow != null)
                AboutWindow.Close();
        }
    }    
}
