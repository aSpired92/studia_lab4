using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using static System.Net.WebRequestMethods;

namespace System_Integrity_Client
{
    internal class Program
    {
        private const string ip = "127.0.0.1";
        private const int port = 5000;


        // checksums lock
        private static object _myLock = new object();
        private static Dictionary<string, string> checksums = new Dictionary<string, string>();

        private static string systemPath = Environment.GetFolderPath(Environment.SpecialFolder.Windows) + @"\System32";

        private static async Task Main(string[] args)
        {
            Console.WriteLine("Zbieranie informacji o plikach systemowych...");
            GetChecksums(systemPath);
            
            Console.WriteLine("Wysyłanie danych na serwer...");
            string data = SerializeChecksums();
            await SendData(Encoding.UTF8.GetBytes(data));

            Console.WriteLine("Wysyłano dane. Naciśnij dowolny klawisz aby kontynuować.");
            Console.ReadKey();
        }

        private static RSAParameters RSAParametersFromString(string str)
        {
            var sr = new System.IO.StringReader(str);
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            return (RSAParameters)xs.Deserialize(sr);
        }

        public static async Task SendData(byte[] data)
        {
            TcpClient client = new TcpClient();
            await client.ConnectAsync(ip, port);

            using (RSA rsa = RSA.Create(2048)) 
            {
                using (Aes aes = Aes.Create()) 
                {
                    aes.Padding = PaddingMode.PKCS7;
                    using (NetworkStream stream = client.GetStream())
                    {
                        List<byte> serverRSAKey = new List<byte>();
                        byte[] buffer = new byte[1024];
                        int bytesRead;
                        while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length)) != 0)
                        {
                            for (int i = 0; i < bytesRead; i++)
                            {
                                serverRSAKey.Add(buffer[i]);
                            }

                            if(bytesRead < buffer.Length)
                            {
                                break;
                            }
                        }

                        RSAParameters param = RSAParametersFromString(Encoding.UTF8.GetString(serverRSAKey.ToArray()));
                        rsa.ImportParameters(param);

                        byte[] encrytpedAesKey = rsa.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA512);
                        byte[] encrytpedAesIV = rsa.Encrypt(aes.IV, RSAEncryptionPadding.OaepSHA512);

                        await stream.WriteAsync(encrytpedAesKey, 0, encrytpedAesKey.Length);
                        await stream.ReadAsync(buffer, 0, buffer.Length);
                        await stream.WriteAsync(encrytpedAesIV, 0, encrytpedAesIV.Length);
                        await stream.ReadAsync(buffer, 0, buffer.Length);

                        ICryptoTransform encryptor = aes.CreateEncryptor();
                        byte[] encryptedData = encryptor.TransformFinalBlock(data, 0, data.Length);
                        await stream.WriteAsync(encryptedData, 0, encryptedData.Length);
                    }
                }
            }
            
            client.Close();
        }

        private static string SerializeChecksums()
        {
            StringBuilder stringBuilder = new StringBuilder();

            foreach (KeyValuePair<string, string> entry in checksums)
            {
                stringBuilder.Append(entry.Key + "|" + entry.Value + "\t");
            }

            return stringBuilder.ToString();
        }

        private static void GetChecksums(string path)
        {
            List<string> directories = GetDirectories(path);
            Task[] taskArray = new Task[directories.Count];

            for (int i = 0; i < directories.Count; i++)
            {
                string d = directories[i];

                taskArray[i] = Task.Factory.StartNew((Object directory) =>
                {
                    try
                    {
                        string strDir = directory as string;

                        string[] files = Directory.GetFiles(strDir);

                        foreach (string p in files)
                        {
                            string temp = GetChecksum(p);

                            if (temp.Equals(string.Empty))
                            {
                                continue;
                            }

                            lock (_myLock)
                            {
                                if (checksums.ContainsKey(p))
                                {
                                    continue;
                                }

                                checksums.Add(p, temp);
                            }
                        }
                    }
                    catch (UnauthorizedAccessException ex)
                    {
                        //Console.WriteLine("Couldn't open " + path + ". Access Denied.");
                    }
                }, d);
            }

            Task.WaitAll(taskArray);
        }

        private static List<string> GetDirectories(string path)
        {
            List<string> directories = new List<string>();

            try
            {
                foreach (string p in Directory.GetDirectories(path))
                {
                    directories.Add(p);
                    foreach (string d in Directory.GetDirectories(p))
                    {
                        directories.Add(d);
                    }
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                //Console.WriteLine("Couldn't enter " + path + ". Access Denied.");
            }

            return directories;
        }

        private static string GetChecksum(string path)
        {
            using (MD5 md5 = MD5.Create())
            {
                try
                {
                    using (FileStream fs = new FileStream(path, FileMode.Open))
                    {
                        byte[] buff = new byte[fs.Length];
                        fs.Read(buff, 0, (int)fs.Length);

                        byte[] checksum = md5.ComputeHash(buff);

                        return BitConverter.ToString(checksum).Replace("-", "").ToLower();
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    //Console.WriteLine("Couldn't open " + path + ". Access Denied.");
                    return string.Empty;
                }
                catch (IOException ex)
                {
                    //Console.WriteLine("Couldn't open " + path + ". It is being used by another process.");
                    return string.Empty;
                }
            }
        }
    }
}