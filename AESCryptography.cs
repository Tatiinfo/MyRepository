using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace EAF.OGIASS.Common.Security
{
    public static class AESCryptography
    {
        #region Settings
        private static int _keySize = 256;
        private static int _blockSize = 128;
        #endregion

        #region Public Methods
        /// <summary>
        /// 
        /// </summary>
        /// <param name="bytesToBeEncrypted">bytes to be encrypted</param>
        /// <param name="password">Password</param>
        /// <param name="saltV"></param>
        /// <returns></returns>
        public static byte[] Encrypt(byte[] bytesToBeEncrypted, string password, string saltV)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                // Create Rijndael object.
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = _keySize;
                    AES.BlockSize = _blockSize;

                    // convert salt to bytes array
                    byte[] salt = Encoding.ASCII.GetBytes(saltV);

                    Rfc2898DeriveBytes derivedKey = new Rfc2898DeriveBytes(password, salt); password = null; saltV = null;
                    //set AES key
                    AES.Key = derivedKey.GetBytes(AES.KeySize / 8);
                    //set initialisation vector
                    AES.IV = derivedKey.GetBytes(AES.BlockSize / 8);
                    //set encryption mode to Cipher Block Chaining
                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        // Start encrypting
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        // Finish encrypting
                        cs.FlushFinalBlock();
                        // Return encrypted bytes array
                        return ms.ToArray();
                    }
                }
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="bytesToBeDecrypted"></param>
        /// <param name="password"></param>
        /// <param name="saltV"></param>
        /// <returns></returns>
        public static byte[] Decrypt(byte[] bytesToBeDecrypted, string password, string saltV)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                // Create Rijndael object
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = _keySize;
                    AES.BlockSize = _blockSize;

                    // convert salt to bytes array
                    byte[] salt = Encoding.ASCII.GetBytes(saltV);

                    Rfc2898DeriveBytes derivedKey = new Rfc2898DeriveBytes(password, salt); password = null; saltV = null;
                    //set AES key
                    AES.Key = derivedKey.GetBytes(AES.KeySize / 8);
                    //set initialisation vector
                    AES.IV = derivedKey.GetBytes(AES.BlockSize / 8);
                    //set decryption mode to Cipher Block Chaining
                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        // Start decrypting
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        // Finish decrypting
                        cs.FlushFinalBlock();
                        // Return decrypted bytes array
                        return ms.ToArray();
                    }
                }
            }
        }
        #endregion
    }
}
