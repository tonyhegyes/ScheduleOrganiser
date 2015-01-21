using System;
using System.IO;
using System.Text;
using System.Security;
using CryptSharp.Utility;
using System.Security.Cryptography;
using System.Runtime.InteropServices;


namespace schedule_organiser.Providers
{
    public class Security
    {
        public RijndaelEncryption UserDataEncryption;
        public string SecureString_toString(SecureString password)
        {
            if (password == null)
                throw new ArgumentNullException("securePassword");

            IntPtr bstr = IntPtr.Zero;
            try
            {
                bstr = Marshal.SecureStringToBSTR(password);
                return Marshal.PtrToStringBSTR(bstr);
            }
            finally { Marshal.ZeroFreeBSTR(bstr); }
        }

        public sealed class RijndaelEncryption
        {
            Rfc2898DeriveBytes pwdGen;
            public RijndaelEncryption(string passPhrase, string salt)
            {
                byte[] Salt = Encoding.ASCII.GetBytes(salt);
                pwdGen = new Rfc2898DeriveBytes(passPhrase, Salt, 10000);
            }

            public byte[] EncryptStringToBytes(string plainText)
            {
                byte[] encrypted;

                using (RijndaelManaged rijAlg = new RijndaelManaged() { BlockSize = 256, Key = pwdGen.GetBytes(32), IV = pwdGen.GetBytes(32), Padding = PaddingMode.ISO10126 })
                {
                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, rijAlg.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                            {
                                swEncrypt.Write(plainText); //Write all data to the stream.
                            }
                            encrypted = msEncrypt.ToArray();
                        }
                    }
                }
                pwdGen.Reset();
                return encrypted;
            }
            public string DecryptStringFromBytes(byte[] cipherText)
            {
                string plaintext = null;

                using (RijndaelManaged rijAlg = new RijndaelManaged() { BlockSize = 256, Key = pwdGen.GetBytes(32), IV = pwdGen.GetBytes(32), Padding = PaddingMode.ISO10126 })
                {
                    using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, rijAlg.CreateDecryptor(), CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                plaintext = srDecrypt.ReadToEnd(); // Read the decrypted bytes from the decrypting stream and place them in a string.
                            }
                        }
                    }
                }
                pwdGen.Reset();
                return plaintext;
            }
            public static string GetBase64sCryptString(string SaltSource, string StringToEncrypt, int memoryCost)
            {
                byte[] Salt = Encoding.ASCII.GetBytes(SaltSource);
                byte[] derivedBytes = SCrypt.ComputeDerivedKey(Encoding.ASCII.GetBytes(StringToEncrypt), (new Rfc2898DeriveBytes(SaltSource, Salt, 10000)).GetBytes(32), (memoryCost != 0 ? memoryCost : 8192), 8, 1, null, 128);
                return Convert.ToBase64String(derivedBytes);
            }
        }
    }
}