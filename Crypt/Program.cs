using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Linq;

namespace Encrypter
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                StartGUI();

            } //For Debugging Purposes only //string[] args = new string[] { "test.txt", "password" , "2"};
            else if (args.Length == 3)
            {
                args3(args);
            }
            else if (args.Length == 4) //Name for saved file.
            {
                if (args[2] == "1")
                {
                    string text = File.ReadAllText(@args[0]);

                    string encryptedStr = StringCipher.Encrypt(text, args[1]);
                    File.WriteAllText(@args[3], encryptedStr);
                    if (encryptedStr.Length >= 10)
                    {
                        Console.WriteLine(encryptedStr.Substring(0, 10));
                    }
                }
                else if (args[2] == "2")
                {
                    string text = File.ReadAllText(@args[0]);

                    string decryptedStr = StringCipher.Decrypt(text, args[1]);
                    File.WriteAllText(@args[3], decryptedStr);
                    if (decryptedStr.Length >= 10)
                    {
                        Console.WriteLine(decryptedStr.Substring(0, 10));
                    }
                }
            }
            else
            {
                Console.WriteLine("You must either use 2 Arguments(Text, Password) or no Arguments.");
            }
        }

        private static void args3(string[] args)
        {
            if (args[2] == "1")
            {
                string text = File.ReadAllText(@args[0]); //Placeholder for args[0]

                string encryptedStr = StringCipher.Encrypt(text, args[1]);
                File.WriteAllText(@"crypted.txt", encryptedStr);
                Console.WriteLine(encryptedStr);
                Console.ReadLine();
            }
            else if (args[2] == "2")
            {
                string text = File.ReadAllText(@args[0]);//Placeholder for args[0]

                string decryptedStr = StringCipher.Decrypt(text, args[1]);
                File.WriteAllText(@"decrypted.txt", decryptedStr);
                Console.WriteLine(decryptedStr);
                Console.ReadLine();

                if (decryptedStr.Length >= 10)
                {
                    Console.WriteLine(decryptedStr.Substring(0, 10));
                }
            }
        }

        static void StartGUI()
        {
            //If not run from console or no arguments open textfield for argument input
            Console.WriteLine("File to encrypt:");
            string file = Console.ReadLine();
            Console.WriteLine("Password:");
            string pswd = Console.ReadLine();
            Console.WriteLine("Destination:");
            string dest = Console.ReadLine();

            if (File.Exists(dest))
            {
                Console.WriteLine("Do you want to overwrite the File? y/n");
                string ans = Console.ReadLine();
                if (ans == "n")
                {
                    StartGUI();
                }
                else if (ans == "y")
                {
                    string text = File.ReadAllText(@file);

                    string encryptedStr = StringCipher.Encrypt(text, pswd);
                    try
                    {
                        File.WriteAllText(dest, encryptedStr);
                    }
                    catch (Exception exception)
                    {
                        Console.WriteLine(exception);
                    }

                    Console.WriteLine("Press Enter to Leave.");
                    Console.ReadLine();
                }
            }
        }
    }

    public static class StringCipher
    {
        private const int Keysize = 128;

        // Number of iterations for the password bytes generation function.
        private const int DerivationIterations = 10000;

        public static string Encrypt(string plainText, string passPhrase)
        {            var saltStringBytes = Generate128BitsOfRandomEntropy();
            var ivStringBytes = Generate128BitsOfRandomEntropy();
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            using (var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations))
            {
                var keyBytes = password.GetBytes(Keysize / 8);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = 128;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    using (var encryptor = symmetricKey.CreateEncryptor(keyBytes, ivStringBytes))
                    {
                        using (var memoryStream = new MemoryStream())
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                            {
                                cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                                cryptoStream.FlushFinalBlock();

                                var cipherTextBytes = saltStringBytes;
                                cipherTextBytes = cipherTextBytes.Concat(ivStringBytes).ToArray();
                                cipherTextBytes = cipherTextBytes.Concat(memoryStream.ToArray()).ToArray();
                                memoryStream.Close();
                                cryptoStream.Close();
                                return Convert.ToBase64String(cipherTextBytes);
                            }
                        }
                    }
                }
            }
        }

        public static string Decrypt(string cipherText, string passPhrase)
        {
            // Get the complete stream of bytes that represent:
            // [32 bytes of Salt] + [32 bytes of IV] + [n bytes of CipherText]
            var cipherTextBytesWithSaltAndIv = Convert.FromBase64String(cipherText);
            // Get the saltbytes by extracting the first 32 bytes from the supplied cipherText bytes.
            var saltStringBytes = cipherTextBytesWithSaltAndIv.Take(Keysize / 8).ToArray();
            // Get the IV bytes by extracting the next 32 bytes from the supplied cipherText bytes.
            var ivStringBytes = cipherTextBytesWithSaltAndIv.Skip(Keysize / 8).Take(Keysize / 8).ToArray();
            // Get the actual cipher text bytes by removing the first 64 bytes from the cipherText string.
            var cipherTextBytes = cipherTextBytesWithSaltAndIv.Skip((Keysize / 8) * 2).Take(cipherTextBytesWithSaltAndIv.Length - ((Keysize / 8) * 2)).ToArray();

            using (var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations))
            {
                var keyBytes = password.GetBytes(Keysize / 8);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = 128;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    using (var decryptor = symmetricKey.CreateDecryptor(keyBytes, ivStringBytes))
                    {
                        using (var memoryStream = new MemoryStream(cipherTextBytes))
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                            {
                                var plainTextBytes = new byte[cipherTextBytes.Length];
                                var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                                memoryStream.Close();
                                cryptoStream.Close();
                                return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
                            }
                        }
                    }
                }
            }
        }

        private static byte[] Generate128BitsOfRandomEntropy()
        {
            var randomBytes = new byte[16]; // 32 Bytes will give us 128 bits.
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                // Fill the array with cryptographically secure random bytes.
                rngCsp.GetBytes(randomBytes);
            }
            return randomBytes;
        }
    }
}
