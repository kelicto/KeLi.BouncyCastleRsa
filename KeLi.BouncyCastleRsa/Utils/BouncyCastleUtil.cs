using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace KeLi.BouncyCastleRsa.Utils
{
    public class BouncyCastleUtil
    {
        public static KeyValuePair<string, string> GenerateKeyPair()
        {
            var keyGenerator = new RsaKeyPairGenerator();
            var parm = new RsaKeyGenerationParameters(BigInteger.ValueOf(3), new SecureRandom(), 1024, 25);

            keyGenerator.Init(parm);

            var keyPair = keyGenerator.GenerateKeyPair();

            var subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            var publicInfoByte = subjectPublicKeyInfo.ToAsn1Object().GetEncoded(Encoding.UTF8.EncodingName);

            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
            var privateInfoByte = privateKeyInfo.ToAsn1Object().GetEncoded(Encoding.UTF8.EncodingName);

            return new KeyValuePair<string, string>(Convert.ToBase64String(publicInfoByte), Convert.ToBase64String(privateInfoByte));
        }

        private static AsymmetricKeyParameter GetPublicKeyParameter(string publicKey)
        {
            publicKey = publicKey.Replace(Environment.NewLine, string.Empty).Trim();

            var publicInfoByte = Convert.FromBase64String(publicKey);

            return PublicKeyFactory.CreateKey(publicInfoByte);
        }

        private static AsymmetricKeyParameter GetPrivateKeyParameter(string privateKey)
        {
            privateKey = privateKey.Replace(Environment.NewLine, string.Empty).Trim();

            var privateInfoByte = Convert.FromBase64String(privateKey);

            return PrivateKeyFactory.CreateKey(privateInfoByte);
        }

        public static string EncryptLongTextByPublicKey(string content, string publicKey)
        {
            var results = new List<string>();
            var maxSubLength = 100;
            var subCount = Math.Ceiling(content.Length / (maxSubLength * 1.0));

            for (var i = 0; i < subCount; i++)
            {
                if (content.Length - i * maxSubLength < maxSubLength)
                    maxSubLength = content.Length - i * maxSubLength;

                var subContent = content.Substring(i * maxSubLength, maxSubLength);
                var subCiphertext = EncryptByPublicKey(subContent, publicKey);

                results.Add(subCiphertext);
            }

            return string.Join(Environment.NewLine, results);
        }

        public static string DecryptLongTextByPrivateKey(string ciphertext, string privateKey)
        {
            var ciphertexts = ciphertext.Split(Environment.NewLine.ToCharArray()).Where(w => !string.IsNullOrWhiteSpace(w)).ToList();

            return ciphertexts.Aggregate(string.Empty, (current, i) => current + DecryptByPrivateKey(i, privateKey));
        }

        public static string EncryptByPublicKey(string content, string publicKey)
        {
            IAsymmetricBlockCipher engine = new Pkcs1Encoding(new RsaEngine());

            engine.Init(true, GetPublicKeyParameter(publicKey));

            var byteData = Encoding.UTF8.GetBytes(content);
            var ciphertextData = engine.ProcessBlock(byteData, 0, byteData.Length);

            return Convert.ToBase64String(ciphertextData);
        }

        public static string DecryptByPrivateKey(string ciphertext, string privateKey)
        {
            ciphertext = ciphertext.Replace(Environment.NewLine, string.Empty).Trim();

            var engine = new Pkcs1Encoding(new RsaEngine());

            engine.Init(false, GetPrivateKeyParameter(privateKey));

            var byteData = Convert.FromBase64String(ciphertext);
            var contentData = engine.ProcessBlock(byteData, 0, byteData.Length);

            return Encoding.UTF8.GetString(contentData);
        }
    }
}