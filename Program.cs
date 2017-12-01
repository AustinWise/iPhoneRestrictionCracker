﻿using System;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace ConsoleApp9
{
    class Program
    {
        const int EXIT_FAILURE = 1;
        const int EXIT_SUCCESS = 0;

        static int Main(string[] args)
        {
            try
            {
                var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                var backupsPath = Path.Combine(appdata, "Apple Computer", "MobileSync", "Backup");

                if (!Directory.Exists(backupsPath))
                {
                    Console.WriteLine("iTunes backup folder does not exist: " + backupsPath);
                    return EXIT_FAILURE;
                }

                foreach (var dir in Directory.GetDirectories(backupsPath))
                {
                    ExtractFromBackup(dir);

                }

                return EXIT_SUCCESS;
            }
            catch (Exception ex)
            {
                Console.WriteLine("PROGRAM CRASHED HORRIBLY");
                Console.WriteLine();
                Console.WriteLine(ex);
                return EXIT_FAILURE;
            }
        }

        private static void ExtractFromBackup(string BACK_PATH)
        {
            var constr = new SQLiteConnectionStringBuilder();
            constr.DataSource = Path.Combine(BACK_PATH, "Manifest.db");

            using (var con = new SQLiteConnection(constr.ToString()))
            {
                con.Open();
                using (var cmd = new SQLiteCommand("select fileId from Files where relativePath like \"%/com.apple.restrictionspassword.plist\"", con))
                using (var reader = cmd.ExecuteReader(System.Data.CommandBehavior.KeyInfo))
                {
                    while (reader.Read())
                    {
                        var fileId = reader.GetString(0);
                        string passwordFilePath = Path.Combine(BACK_PATH, fileId.Substring(0, 2), fileId);

                        var doc = XDocument.Load(passwordFilePath);
                        var datas = doc.Root.Element("dict").Elements("data").ToArray();

                        var key = Convert.FromBase64String(datas[0].Value);
                        var salt = Convert.FromBase64String(datas[1].Value);

                        Console.WriteLine();

                        bool foundPassword = false;

                        Parallel.For(0, 10000, pw =>
                        {
                            if (foundPassword)
                                return;

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
                            foundPassword = true;
                        });

                    }
                    Console.WriteLine("done");
                }
            }
        }
    }
}
