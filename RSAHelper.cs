using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace WeViking.Util
{
    /// <summary>
    /// 版 本 WeViking-Business v1.0
    /// Copyright (c) 2013-2017 xgluxv
    /// 创建人：xgluxv
    /// 日 期：2017.03.04
    /// 描 述：数据访问(SqlServer) 上下文
    /// </summary>
    public class RSAHelper
    {
        #region "RSA加密"
        /*
        //密钥对，请配合密钥生成工具使用『 http://download.csdn.net/detail/downiis6/9464639 』
        private const string PublicRsaKey = @"<RSAKeyValue>
 <Modulus>8Yvf/LjXRhCuOREk2CuSYvbD/RadwJ4sjHREIpQVKwkTlG3BtRgpnaMcoeLAesmwvpBWnqK4hBkYLxhRj+NEKnlGrJ+LkNMnZr0/4CMuulZFAnx7iQYaSq7Eh7kBKGLofc05CjZguYpnPNxHIv4VNx+a9tIh+hnhjrmkJLUm3l0=</Modulus>
 <Exponent>AQAB</Exponent>
</RSAKeyValue>";
        private const string PrivateRsaKey = @"<RSAKeyValue>
 <Modulus>8Yvf/LjXRhCuOREk2CuSYvbD/RadwJ4sjHREIpQVKwkTlG3BtRgpnaMcoeLAesmwvpBWnqK4hBkYLxhRj+NEKnlGrJ+LkNMnZr0/4CMuulZFAnx7iQYaSq7Eh7kBKGLofc05CjZguYpnPNxHIv4VNx+a9tIh+hnhjrmkJLUm3l0=</Modulus>
 <Exponent>AQAB</Exponent>
 <P>/xAaa/4dtDxcEAk5koSZBPjuxqvKJikpwLA1nCm3xxAUMDVxSwQyr+SHFaCnBN9kqaNkQCY6kDCfJXFWPOj0Bw==</P>
 <Q>8m8PFVA4sO0oEKMVQxt+ivDTHFuk/W154UL3IgC9Y6bzlvYewXZSzZHmxZXXM1lFtwoYG/k+focXBITsiJepew==</Q>
 <DP>ONVSvdt6rO2CKgSUMoSfQA9jzRr8STKE3i2lVG2rSIzZosBVxTxjOvQ18WjBroFEgdQpg23BQN3EqGgvqhTSQw==</DP>
 <DQ>gfp7SsEM9AbioTDemHEoQlPly+FyrxE/9D8UAt4ErGX5WamxSaYntOGRqcOxcm1djEpULMNP90R0Wc7uhjlR+w==</DQ>
 <InverseQ>C0eBsp2iMOxWwKo+EzkHOP0H+YOitUVgjekGXmSt9a3TvikQNaJ5ATlqKsZaMGsnB6UIHei+kUaCusVX0HgQ2A==</InverseQ>
 <D>tPYxEfo9Nb3LeO+SJe3G1yO+w37NIwCdqYB1h15f2YUMSThNVmpKy1HnYpUp1RQDuVETw/duu3C9gJL8kAsZBjBrVZ0zC/JZsgvSNprfUK3Asc4FgFsGfQGKW1nvvgdMbvqr4ClB0R8czkki+f9Oc5ea/RMqXxlI+XjzMYDEknU=</D>
</RSAKeyValue>";
        */
        /// <summary>
        /// RSA 加密
        /// </summary>
        public static string Rsa(string PublicRsaKey, string source)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlStringExtensions(PublicRsaKey);
            var cipherbytes = rsa.Encrypt(Encoding.UTF8.GetBytes(source), false);
            return Convert.ToBase64String(cipherbytes);
        }

        /// <summary>
        /// RSA解密
        /// </summary>
        public static string UnRsa(string PrivateRsaKey, string source)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlStringExtensions(PrivateRsaKey);
            var bytes = Convert.FromBase64String(source);
            var cipherbytes = rsa.Decrypt(bytes, false);
            return Encoding.UTF8.GetString(cipherbytes);
        }

        private static RsaKeyParameters RSAXMLPublicKeyToBouncyCastleKeyParameter(string publicKey)
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(publicKey);
            BigInteger m = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Modulus")[0].InnerText));
            BigInteger p = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Exponent")[0].InnerText));
            RsaKeyParameters pub = new RsaKeyParameters(false, m, p);

            return pub;
        }

        public static string RSADecryptByPublicKey(string xmlPublicKey, string strEncryptString)
        {
            //得到公钥
            RsaKeyParameters keyParams = RSAXMLPublicKeyToBouncyCastleKeyParameter(xmlPublicKey);

            //参数与Java中加密解密的参数一致
            IBufferedCipher c = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");

            //第一个参数 true-加密，false-解密；第二个参数表示密钥
            c.Init(false, keyParams);

            //对密文进行base64解码
            byte[] dataFromEncrypt = Convert.FromBase64String(strEncryptString);

            var MAX_BLOCK = 128;
            int inputLen = dataFromEncrypt.Length;

            using (var outStream = new System.IO.MemoryStream())
            {
                using (var write = new System.IO.BinaryWriter(outStream))
                {
                    //分段解密
                    int offset = 0;
                    for (int i = 0; inputLen - offset > 0; offset = i * MAX_BLOCK)
                    {
                        byte[] cache;
                        if (inputLen - offset > MAX_BLOCK)
                        {
                            cache = c.DoFinal(dataFromEncrypt, offset, MAX_BLOCK);
                        }
                        else
                        {
                            cache = c.DoFinal(dataFromEncrypt, offset, inputLen - offset);
                        }
                        write.Write(cache, 0, cache.Length);
                        //out.write(cache, 0, cache.length);
                        ++i;
                    }

                    byte[] outBytes = outStream.ToArray();
                    //明文
                    string clearText = Encoding.UTF8.GetString(outBytes);
                    return clearText;
                }

            }


        //解密
        //byte[] outBytes = c.DoFinal(dataFromEncrypt,0,256);


        }

        #endregion
    }

    public static class RSACryptoServiceProviderExtensions
    {
        public static void FromXmlStringExtensions(this RSACryptoServiceProvider rsa, string xmlString)
        {
            RSAParameters parameters = new RSAParameters();

            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlString);

            if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
            {
                foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                {
                    switch (node.Name)
                    {
                        case "Modulus": parameters.Modulus = Convert.FromBase64String(node.InnerText); break;
                        case "Exponent": parameters.Exponent = Convert.FromBase64String(node.InnerText); break;
                        case "P": parameters.P = Convert.FromBase64String(node.InnerText); break;
                        case "Q": parameters.Q = Convert.FromBase64String(node.InnerText); break;
                        case "DP": parameters.DP = Convert.FromBase64String(node.InnerText); break;
                        case "DQ": parameters.DQ = Convert.FromBase64String(node.InnerText); break;
                        case "InverseQ": parameters.InverseQ = Convert.FromBase64String(node.InnerText); break;
                        case "D": parameters.D = Convert.FromBase64String(node.InnerText); break;
                    }
                }
            }
            else
            {
                throw new Exception("Invalid XML RSA key.");
            }

            rsa.ImportParameters(parameters);
        }

        public static string ToXmlString(this RSACryptoServiceProvider rsa)
        {
            RSAParameters parameters = rsa.ExportParameters(true);

            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                Convert.ToBase64String(parameters.Modulus),
                Convert.ToBase64String(parameters.Exponent),
                Convert.ToBase64String(parameters.P),
                Convert.ToBase64String(parameters.Q),
                Convert.ToBase64String(parameters.DP),
                Convert.ToBase64String(parameters.DQ),
                Convert.ToBase64String(parameters.InverseQ),
                Convert.ToBase64String(parameters.D));
        }
    }
}