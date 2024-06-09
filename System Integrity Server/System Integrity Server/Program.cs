using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.IO;
using System;

namespace System_Integrity_Server
{
    internal class Program
    {
        private const int Port = 5000;

        private static object _lockFile = new object();
        private static string checksumFile = @"./checksums.txt";
        private static Dictionary<string, string> checksums = new Dictionary<string, string>();

        static async Task Main(string[] args)
        {
            if (File.Exists(checksumFile)) 
            {
                using (FileStream fs = new FileStream(checksumFile, FileMode.Open))
                {
                    using (StreamReader sr = new StreamReader(fs)) 
                    {
                        string temp = sr.ReadToEnd();
                        checksums = DeserializeChecksums(temp);
                    }
                }
            }
            await StartServerAsync();
        }

        private static async Task StartServerAsync()
        {
            TcpListener listener = new TcpListener(IPAddress.Any, Port);
            listener.Start();
            Console.WriteLine("Serwer uruchomiony, oczekiwanie na połączenia...");
            while (true)
            {
                TcpClient client = await listener.AcceptTcpClientAsync();
                Console.WriteLine("Połączono z klientem.");
                _ = HandleClientAsync(client);
            }
        }

        private static string RSAParametersToString(RSAParameters param)
        {
            var sw = new System.IO.StringWriter();
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, param);
            return sw.ToString();
        }

        private static async Task HandleClientAsync(TcpClient client)
        {
            IPEndPoint endPoint = (IPEndPoint)client.Client.RemoteEndPoint;

            string clientIP = endPoint.Address.ToString();
            string message = @"";

            using (RSA rsa = RSA.Create(2048)) 
            {
                RSAParameters serverPrivateKey = rsa.ExportParameters(true);
                RSAParameters serverPublicKey = rsa.ExportParameters(false);

                using (NetworkStream stream = client.GetStream())
                {
                    Console.WriteLine(clientIP + ": Wysyłanie klucza publicznego");
                    byte[] serverPublicKeyBytes = Encoding.UTF8.GetBytes(RSAParametersToString(serverPublicKey));
                    await stream.WriteAsync(serverPublicKeyBytes, 0, serverPublicKeyBytes.Length);

                    Console.WriteLine(clientIP + ": Odczytywanie klucza szyfrującego AES");
                    List<byte> aesKeyEncrypted = new List<byte>();
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length)) != 0)
                    {
                        for(int i=0; i<bytesRead; i++) 
                        {
                            aesKeyEncrypted.Add(buffer[i]);
                        }

                        if (bytesRead < buffer.Length)
                        {
                            break;
                        }
                    }
                    byte[] aesKey = rsa.Decrypt(aesKeyEncrypted.ToArray(), RSAEncryptionPadding.OaepSHA512);

                    byte[] response = Encoding.UTF8.GetBytes("OK");
                    await stream.WriteAsync(response, 0, response.Length);

                    Console.WriteLine(clientIP + ": Odczytywanie IV AES");
                    List<byte> aesIVEncrypted = new List<byte>();
                    buffer = new byte[1024];
                    while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length)) != 0)
                    {
                        for (int i = 0; i < bytesRead; i++)
                        {
                            aesIVEncrypted.Add(buffer[i]);
                        }

                        if (bytesRead < buffer.Length)
                        {
                            break;
                        }
                    }
                    byte[] aesIV = rsa.Decrypt(aesIVEncrypted.ToArray(), RSAEncryptionPadding.OaepSHA512);

                    await stream.WriteAsync(response, 0, response.Length);

                    Console.WriteLine(clientIP + ": Odbieranie danych");
                    List<byte> dataEncrypted = new List<byte>();
                    buffer = new byte[1024];
                    while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length)) != 0)
                    {
                        for (int i = 0; i < bytesRead; i++)
                        {
                            dataEncrypted.Add(buffer[i]);
                        }

                        if (bytesRead < buffer.Length)
                        {
                            break;
                        }
                    }

                    byte[] data;
                    using (Aes aes = Aes.Create())
                    {
                        aes.Padding = PaddingMode.PKCS7;
                        aes.Key = aesKey;
                        aes.IV = aesIV;

                        ICryptoTransform decryptor = aes.CreateDecryptor();

                        data = decryptor.TransformFinalBlock(dataEncrypted.ToArray(), 0, dataEncrypted.ToArray().Length);
                    }

                    message = Encoding.UTF8.GetString(data);
                }
            }
            
            

            client.Close(); 
            Console.WriteLine(clientIP + ": Klient rozłączony");
            Console.WriteLine(clientIP + ": Sprawdzanie sum kontrolnych");
            Dictionary<string, string> sentChecksums = DeserializeChecksums(message);

            List<string> wrongChecksums = CompareChecksums(sentChecksums);

            if (wrongChecksums.Count > 0)
            {
                if (!EventLog.SourceExists("System Integrity"))
                {
                    EventLog.CreateEventSource("System Integrity", "MyNewLog");
                }

                EventLog eventLog = new EventLog();
                eventLog.Source = "System Integrity";
                string msg = clientIP + ": Niektóre pliki systemowe mają inne sumy kontrolne:\n\n";

                foreach (string checksum in wrongChecksums) 
                {
                    msg += checksum + "\n";
                }

                Console.WriteLine(msg);
                eventLog.WriteEntry(msg, EventLogEntryType.Error);
            }

            lock(_lockFile)
            {
                using(FileStream fs = new FileStream(checksumFile,FileMode.Create))
                {
                    using (StreamWriter sw = new StreamWriter(fs)) 
                    {
                        sw.Write(SerializeChecksums());
                    }
                }
            }
        }

        private static Dictionary<string, string> DeserializeChecksums(string data)
        {
            Dictionary<string, string> result = new Dictionary<string, string>();

            string[] lines = data.Split('\t');
            foreach (string line in lines)
            {
                try
                {
                    string[] parts = line.Split('|');

                    if (parts.Length < 2)
                    {
                        continue;
                    }

                    string path = parts[0];
                    string checksum = parts[1];

                    result.Add(path, checksum);
                }
                catch
                {}
            }

            return result;
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

        private static List<string> CompareChecksums(Dictionary<string, string> data) 
        {
            List<string> result = new List<string>();
            
            foreach (KeyValuePair<string, string> entry in data) 
            {
                if(!checksums.ContainsKey(entry.Key))
                {
                    checksums.Add(entry.Key, entry.Value);
                    continue;
                }

                if (!entry.Value.Equals(checksums[entry.Key]))
                {
                    result.Add(entry.Key);
                }
            }

            return result;
        }
    }
}