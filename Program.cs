using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace ConsoleApp9
{
    class Program
    {
        static void Main(string[] args)
        {
            const string BACK_PATH = @"C:\Users\awise\AppData\Roaming\Apple Computer\MobileSync\Backup\da4aeff7d56179a2f7707e9805567d6c82a65e71";
            const string PLUTIL = @"C:\Program Files (x86)\Common Files\Apple\Apple Application Support\plutil.exe";
            const string WORK_DIR = @"C:\temp\plist";

            var constr = new SQLiteConnectionStringBuilder();
            constr.DataSource = Path.Combine(BACK_PATH, "Manifest.db");

            using (var con = new SQLiteConnection(constr.ToString()))
            {
                con.Open();
                using (var cmd = new SQLiteCommand("select fileId, domain from Files where relativePath like \"%/com.apple.restrictionspassword.plist\"", con))
                using (var reader = cmd.ExecuteReader(System.Data.CommandBehavior.KeyInfo))
                {
                    while (reader.Read())
                    {
                        var fileId = reader.GetString(0);
                        var domain = reader.GetString(1);
                        Console.WriteLine($"{domain}: {fileId}");
                        string filename = domain + ".xml";
                        string destPath = Path.Combine(WORK_DIR, filename);
                        File.Copy(Path.Combine(BACK_PATH, fileId.Substring(0, 2), fileId), destPath, true);
                        File.SetAttributes(destPath, File.GetAttributes(destPath) & ~FileAttributes.ReadOnly);

                        ProcessStartInfo startInfo = new ProcessStartInfo(PLUTIL, $"-convert xml1 {filename}");
                        startInfo.UseShellExecute = false;
                        startInfo.WorkingDirectory = WORK_DIR;
                        var p = Process.Start(startInfo);
                        p.WaitForExit();

                        var doc = XDocument.Load(destPath);
                        var datas = doc.Root.Element("dict").Elements("data").ToArray();

                        var key = Convert.FromBase64String(datas[0].Value);
                        var salt = Convert.FromBase64String(datas[1].Value);

                        Console.WriteLine();

                        Parallel.For(0, 10000, pw =>
                        {
                            var pwstr = pw.ToString("0000");
                            byte[] bytes;
                            using (var der = new MyRfc2898DeriveBytes(pwstr, salt, 1000))
                            {
                                bytes = der.GetBytes(20);
                            }

                            for (int i = 0; i < key.Length; i++)
                            {
                                if (key[i] != bytes[i])
                                    return;
                            }

                            Console.WriteLine(pwstr);
                        });

                    }
                    Console.WriteLine("done");
                }
            }
        }

    }
}
