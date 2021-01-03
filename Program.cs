using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Asn1;
using System.IO;

namespace RSADecryptWithJava
{
    class Program
    {
        static void Main(string[] args)
        {
            var publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRF6YT5YV4QJ5a+6PMG1CruOO/RbT7Of1ze/uOat+jkakigQtCTxBYDs1TGhLwEUckl2gXMYH89xZ2d0dfHaPvtpYA3/NmQfofKmt7cn49I4VEFH3Su46rXtrXeYktC7LNgT35wXEe9Alwdpcys/JWSlcluhZtIEQRYBpmaD2/jQIDAQAB";
            var data = "z1QvY9TqEY0HAZOPBhECRjdS/lrjQABjBjP2FcM+7oNE71TdR3if+G0FfpCF8M6Zzsjv+HNabIpi1D8Dpk7FmY6HlnpHQyDdk0Qtw04zmKtENtlgYyYzd3RhJhgDCGJ64rP5PvA6fgklNlsd8i5VgnS41jPXFkyNeIZQZcwuQ9IF1xIrUDLmmwi5Ab0Sz5jYCjWcROt4H/CqrPFAh4EoDzOA4xTP6Xr5hzP5yjQNUmEe4LAthr2jP1sG/atf0CGNc7yFm3a9MC+fO18QYCTuZ4pa55c79p6QN70X5ZwA13x+jw3eeWOEXWK3WWd4eL74loD3yMuqZIwbgTTEQ2xZtQ==";

            IAsymmetricBlockCipher engine = new Pkcs1Encoding(new RsaEngine());
            try
            {
                engine.Init(false, GetPublicKeyParameter(publicKey));
                byte[] byteData = Convert.FromBase64String(data);
                var block_size = 128;
                using(MemoryStream ms = new MemoryStream())
                {
                    int offset = 0;
                    while (byteData.Length - offset > 0)
                    {
                        var cache = engine.ProcessBlock(byteData, offset, block_size);
                        ms.Write(cache, 0, cache.Length);
                        offset += block_size;
                    }
                    var buffer = ms.ToArray();
                    var clearTxt = System.Text.Encoding.UTF8.GetString(buffer);
                    Console.WriteLine(clearTxt);
                }
                Console.ReadLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                
            }
        }

        static AsymmetricKeyParameter GetPublicKeyParameter(string s)
        {
            s = s.Replace("\r", "").Replace("\n", "").Replace(" ", "");
            byte[] publicInfoByte = Convert.FromBase64String(s);
            Asn1Object pubKeyObj = Asn1Object.FromByteArray(publicInfoByte);//这里也可以从流中读取，从本地导入   
            AsymmetricKeyParameter pubKey = PublicKeyFactory.CreateKey(publicInfoByte);
            return pubKey;
        }

        
    }
}
