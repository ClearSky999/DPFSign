using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using iTextSharp.text.pdf.security;
using iTextSharp.text.pdf;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using System.IO;
using iTextSharp.text;
using System.Web.Script.Serialization;
using System.Text;
using System.Security.Cryptography;
// C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe C:\code\DelphiTest\DPFSign.dll
namespace CSharpDPFSign
{
    public interface ICSharpSignature
    {
        
        string returnInput(string str);

       string Sign(string pdfBase64, string imgBase64, string certBase64, string certPwd, string reason, string location);
    }

    [ClassInterface(ClassInterfaceType.None)]
    [Guid("5EBEF63C-2ED4-49E3-8C0E-ADD5FA08549B")] //{5EBEF63C-2ED4-49E3-8C0E-ADD5FA08549B}
    [ProgId("ICSharpSignature.CSharpSignature")]
    public class CSharpSignature : ICSharpSignature
    {
     
        public string returnInput(string str)
        {
            
            return "你输入的是:" + str;
        }
    
        /// <summary>
        /// 
        /// </summary>
        /// <param name="pdf">pdf的文件流</param>
        /// <param name="img">签章图片的文件流</param>
        /// <param name="cert">证书的文件流</param>
        /// <param name="certPwd">证书的密码</param>
        /// <param name="reason">签发时原因</param>
        /// <param name="location">签发时位置</param>
        /// <returns></returns>
        public string Sign(string pdfBase64, string imgBase64, string certBase64, string certPwd, string reason, string location)
        {
            string path = Directory.GetCurrentDirectory() + "\\log.log";
            Dictionary<string, object> resDic = new Dictionary<string, object>
        {
            { "success", true },
            { "data", "" },
            { "msg",""}
        };
           File.AppendAllText(path, "\r\n " + resDic.ToString());
            try
            {
               
                byte[] imgbytes = Convert.FromBase64String(imgBase64);
                byte[] certbytes = Convert.FromBase64String(certBase64);
             
                MemoryStream pdfMS = ConvertLargeBase64StringToStream(pdfBase64); // new MemoryStream(pdfbytes);
          

                MemoryStream imgMS = new MemoryStream(imgbytes);
                MemoryStream certMS = new MemoryStream(certbytes);
                string certificatePassword = certPwd;// "123456";
                MemoryStream outputStream = new MemoryStream();
                pdfMS.Position = 0;
                PdfReader reader = new PdfReader(pdfMS);
                PdfStamper stamper = PdfStamper.CreateSignature(reader, outputStream, '\0');
            
                PdfSignatureAppearance appearance = stamper.SignatureAppearance;
                appearance.Reason = reason;
                appearance.Location = location;

            

                // 读取图片
                iTextSharp.text.Image image = iTextSharp.text.Image.GetInstance(imgMS); // Image.GetInstance(imagePath);
                                                                                        // image.ScaleToFit(50, 50);
                appearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.GRAPHIC;
                appearance.SignatureGraphic = image;
             

                iTextSharp.text.Rectangle pageSize = reader.GetPageSize(reader.NumberOfPages);
                double width = appearance.SignatureGraphic.Width * 0.5;
                double height = appearance.SignatureGraphic.Height * 0.5;
                int x = (int)(pageSize.Width - width);
                int y = (int)(pageSize.Height - height);
                // 设置签名的位置
                float pyVal = 200;
                var Rectangle = new Rectangle(x - pyVal, pyVal, pageSize.Width - pyVal, (float)height + pyVal);
                
                appearance.SetVisibleSignature(Rectangle, reader.NumberOfPages, "Signature");
              

                Pkcs12Store store;
            

                store = new Pkcs12Store(certMS, certificatePassword.ToCharArray());

                string alias = null;
                foreach (string al in store.Aliases)
                {
                    if (store.IsKeyEntry(al) && store.GetKey(al).Key.IsPrivate)
                    {
                        alias = al;
                        break;
                    }
                }

                AsymmetricKeyParameter pk = store.GetKey(alias).Key;
                X509CertificateEntry[] ce = store.GetCertificateChain(alias);
                Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[ce.Length];
                for (int k = 0; k < ce.Length; ++k)
                {
                    chain[k] = ce[k].Certificate;
                }

                IExternalSignature pks = new PrivateKeySignature(pk, "SHA-256");

                MakeSignature.SignDetached(appearance, pks, chain, null, null, null, 0, CryptoStandard.CMS);

             

                 
                byte[] signedPdf = outputStream.ToArray();
                string base64 = Convert.ToBase64String(signedPdf); //ToBase64(signedPdf);
                certMS.Close();
                pdfMS.Close();
                imgMS.Close();
                outputStream.Close();
                reader.Close();
                stamper.Close();
                resDic["data"] =   base64;

            }
            catch (Exception ex)
            {
                File.AppendAllText(path, "\r\n "+ ex.ToString());
                resDic["data"] = ex.Message.ToString();
                resDic["success"] = false;

            }
         
            var serializer = new JavaScriptSerializer();

            // 设置最大长度为500MB
          serializer.MaxJsonLength = 500 * 1024 * 1024;
            string json = serializer.Serialize(resDic);
        
            return json;
        }


        private MemoryStream ConvertLargeBase64StringToStream(string base64String)
        {
            int blockSize = 4 * 1024; // 4KB blocks
            int byteBlockSize = (int)Math.Ceiling((double)blockSize * 3 / 4); // Size must be multiple of 4

            MemoryStream memoryStream = new MemoryStream();
            for (int i = 0; i < base64String.Length; i += blockSize)
            {
                int length = blockSize;
                if (i + blockSize > base64String.Length)
                {
                    length = base64String.Length - i;
                }

                byte[] bytes = Convert.FromBase64String(base64String.Substring(i, length));
                memoryStream.Write(bytes, 0, bytes.Length);
            }

            memoryStream.Position = 0; // Optional: Reset position to start of stream
            return memoryStream;
        }

        public string ToBase64(byte[] data)
        {
            const int blockSize = 1024; // 使用适合的块大小
            StringBuilder result = new StringBuilder((int)(data.Length * 2)); // 预先分配足够的空间

            for (int i = 0; i < data.Length; i += blockSize)
            {
                int length = Math.Min(blockSize, data.Length - i);
                result.Append(Convert.ToBase64String(data, i, length));
            }

            return result.ToString();
        }





















        /// <summary>
        /// 
        /// </summary>
        /// <param name="pdf">pdf的文件流</param>
        /// <param name="img">签章图片的文件流</param>
        /// <param name="cert">证书的文件流</param>
        /// <param name="certPwd">证书的密码</param>
        /// <param name="reason">签发时原因</param>
        /// <param name="location">签发时位置</param>
        /// <returns></returns>
        public Dictionary<string, object> SignSteam(Stream pdf, Stream img, Stream cert, string certPwd, string reason, string location)
        {
            Dictionary<string, object> resDic = new Dictionary<string, object>
        {
            { "success", true },
            { "data", "" },
            { "msg",""}
        };
            // var pDFSignaInterface = new PDFSignaClass();
            try
            {
                string certificatePassword = certPwd;// "123456";
                MemoryStream outputStream = new MemoryStream();
                pdf.Position = 0;
                PdfReader reader = new PdfReader(pdf);
                PdfStamper stamper = PdfStamper.CreateSignature(reader, outputStream, '\0');
                PdfSignatureAppearance appearance = stamper.SignatureAppearance;
                appearance.Reason = reason;
                appearance.Location = location;

                // System.Drawing.Image signImg = System.Drawing.Image.FromStream(img);


                // 读取图片
                iTextSharp.text.Image image = iTextSharp.text.Image.GetInstance(img); // Image.GetInstance(imagePath);
                                                                                      // image.ScaleToFit(50, 50);
                appearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.GRAPHIC;
                appearance.SignatureGraphic = image;
                // appearance.Image = image;
                // 获取PDF的最后一页的大小

                iTextSharp.text.Rectangle pageSize = reader.GetPageSize(reader.NumberOfPages);
                double width = appearance.SignatureGraphic.Width * 0.5;
                double height = appearance.SignatureGraphic.Height * 0.5;
                int x = (int)(pageSize.Width - width);
                int y = (int)(pageSize.Height - height);
                // 设置签名的位置
                float pyVal = 200;
                var Rectangle = new Rectangle(x - pyVal, pyVal, pageSize.Width - pyVal, (float)height + pyVal);
                //  var Rectangle = new iTextSharp.text.Rectangle(200,0, (float)width, (float)height);
                appearance.SetVisibleSignature(Rectangle, reader.NumberOfPages, "Signature");
                //  var fileStream = new FileStream(certificatePath, FileMode.Open);

                Pkcs12Store store;
                // using (var fileStream = new FileStream(certificatePath, FileMode.Open))
                // {
                //     store = new Pkcs12Store(fileStream, certificatePassword.ToCharArray());
                // }

                store = new Pkcs12Store(cert, certificatePassword.ToCharArray());

                string alias = null;
                foreach (string al in store.Aliases)
                {
                    if (store.IsKeyEntry(al) && store.GetKey(al).Key.IsPrivate)
                    {
                        alias = al;
                        break;
                    }
                }

                AsymmetricKeyParameter pk = store.GetKey(alias).Key;
                X509CertificateEntry[] ce = store.GetCertificateChain(alias);
                Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[ce.Length];
                for (int k = 0; k < ce.Length; ++k)
                {
                    chain[k] = ce[k].Certificate;
                }


                IExternalSignature pks = new PrivateKeySignature(pk, "SHA-256");

                MakeSignature.SignDetached(appearance, pks, chain, null, null, null, 0, CryptoStandard.CMS);
                byte[] signedPdf = outputStream.ToArray();
                string base64 = Convert.ToBase64String(signedPdf);
                cert.Close();
                outputStream.Close();
                reader.Close();
                stamper.Close();
                resDic["data"] = base64;

            }
            catch (Exception ex)
            {
                resDic["data"] = ex.Message.ToString();
                resDic["success"] = false;

            }
            return resDic;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="pdf">pdf的文件流</param>
        /// <param name="img">签章图片的文件流</param>
        /// <param name="cert">证书的文件流</param>
        /// <param name="certPwd">证书的密码</param>
        /// <param name="reason">签发时原因</param>
        /// <param name="location">签发时位置</param>
        /// <returns></returns>
        public string SignByte(Byte[] pdfbytes, Byte[] imgbytes, Byte[] certbytes, string certPwd, string reason, string location)
        {
            Dictionary<string, object> resDic = new Dictionary<string, object>
        {
            { "success", true },
            { "data", "" },
            { "msg",""}
        };
            // var pDFSignaInterface = new PDFSignaClass();
            try
            {
                MemoryStream pdfMS = new MemoryStream(pdfbytes);
                MemoryStream imgMS = new MemoryStream(imgbytes);
                MemoryStream certMS = new MemoryStream(certbytes);
                string certificatePassword = certPwd;// "123456";
                MemoryStream outputStream = new MemoryStream();
                pdfMS.Position = 0;
                PdfReader reader = new PdfReader(pdfMS);
                PdfStamper stamper = PdfStamper.CreateSignature(reader, outputStream, '\0');
                PdfSignatureAppearance appearance = stamper.SignatureAppearance;
                appearance.Reason = reason;
                appearance.Location = location;

                // System.Drawing.Image signImg = System.Drawing.Image.FromStream(img);


                // 读取图片
                iTextSharp.text.Image image = iTextSharp.text.Image.GetInstance(imgMS); // Image.GetInstance(imagePath);
                                                                                        // image.ScaleToFit(50, 50);
                appearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.GRAPHIC;
                appearance.SignatureGraphic = image;
                // appearance.Image = image;
                // 获取PDF的最后一页的大小

                iTextSharp.text.Rectangle pageSize = reader.GetPageSize(reader.NumberOfPages);
                double width = appearance.SignatureGraphic.Width * 0.5;
                double height = appearance.SignatureGraphic.Height * 0.5;
                int x = (int)(pageSize.Width - width);
                int y = (int)(pageSize.Height - height);
                // 设置签名的位置
                float pyVal = 200;
                var Rectangle = new Rectangle(x - pyVal, pyVal, pageSize.Width - pyVal, (float)height + pyVal);
                //  var Rectangle = new iTextSharp.text.Rectangle(200,0, (float)width, (float)height);
                appearance.SetVisibleSignature(Rectangle, reader.NumberOfPages, "Signature");
                //  var fileStream = new FileStream(certificatePath, FileMode.Open);

                Pkcs12Store store;
                // using (var fileStream = new FileStream(certificatePath, FileMode.Open))
                // {
                //     store = new Pkcs12Store(fileStream, certificatePassword.ToCharArray());
                // }

                store = new Pkcs12Store(certMS, certificatePassword.ToCharArray());

                string alias = null;
                foreach (string al in store.Aliases)
                {
                    if (store.IsKeyEntry(al) && store.GetKey(al).Key.IsPrivate)
                    {
                        alias = al;
                        break;
                    }
                }

                AsymmetricKeyParameter pk = store.GetKey(alias).Key;
                X509CertificateEntry[] ce = store.GetCertificateChain(alias);
                Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[ce.Length];
                for (int k = 0; k < ce.Length; ++k)
                {
                    chain[k] = ce[k].Certificate;
                }


                IExternalSignature pks = new PrivateKeySignature(pk, "SHA-256");

                MakeSignature.SignDetached(appearance, pks, chain, null, null, null, 0, CryptoStandard.CMS);
                byte[] signedPdf = outputStream.ToArray();
                string base64 = Convert.ToBase64String(signedPdf);
                certMS.Close();
                pdfMS.Close();
                imgMS.Close();
                outputStream.Close();
                reader.Close();
                stamper.Close();
                resDic["data"] = base64;

            }
            catch (Exception ex)
            {

                resDic["data"] = ex.Message.ToString();
                resDic["success"] = false;

            }
            string json = new JavaScriptSerializer().Serialize(resDic);
            return json;
        }

    }


}


