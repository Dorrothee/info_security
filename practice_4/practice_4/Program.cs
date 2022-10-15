using System.Security.Cryptography;
using System.Text;
class HashProgram
{
    public static void Main()
    {
        int c_hmac1 = 0;
        string[] data_hmac1 = new string[10];
        int c_hmac256 = 0;
        string[] data_hmac256 = new string[10];
        int c_hmac512 = 0;
        string[] data_hmac512 = new string[10];
        int c_hmacmd5 = 0;
        string[] data_hmacmd5 = new string[10];
        do
        {
            Console.WriteLine("List of HMAC can be used:");
            Console.WriteLine("1 - HMACSHA1");
            Console.WriteLine("2 - HMACSHA256");
            Console.WriteLine("3 - HMACSHA512");
            Console.WriteLine("4 - HMACMD5");
            Console.WriteLine("5 - exit");
            Console.WriteLine("Which HMAC you want to use: ");
            int option = Convert.ToInt32(Console.ReadLine());
            Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            switch (option)
            {
                case 1:
                    Console.WriteLine("Enter the message to find a hash via HMACSHA1:");
                    string hmac1_input = Console.ReadLine();
                    Console.WriteLine("Enter the password for your message:");
                    string hmac1pas_input = null;
                    while (true)
                    {
                        var key = Console.ReadKey(true);
                        if (key.Key == ConsoleKey.Enter)
                            break;
                        hmac1pas_input += key.KeyChar;
                    }
                    byte[] hmac1_byte = Encoding.Unicode.GetBytes(hmac1_input);
                    byte[] hmac1pas_byte = Encoding.Unicode.GetBytes(hmac1pas_input);
                    var hmac1forinput = ComputeHMACSHA1(hmac1_byte, hmac1pas_byte);
                    data_hmac1[c_hmac1] = Convert.ToBase64String(hmac1forinput);
                    Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    Console.WriteLine("Do you want to verify your message?");
                    Console.WriteLine("1 - yes");
                    Console.WriteLine("2 - no");
                    Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    string choice_1 = Console.ReadLine();
                    if (choice_1 == "yes")
                    {
                        Console.WriteLine("Enter your message:");
                        string hmac1_verify = Console.ReadLine();
                        Console.WriteLine("Enter the password for your message:");
                        string hmac1pas_verify = null;
                        while (true)
                        {
                            var key = Console.ReadKey(true);
                            if (key.Key == ConsoleKey.Enter)
                                break;
                            hmac1pas_verify += key.KeyChar;
                        }
                        byte[] hmac1_verify_byte = Encoding.Unicode.GetBytes(hmac1_verify);
                        byte[] hmac1pas_verify_byte = Encoding.Unicode.GetBytes(hmac1pas_verify);
                        var hmac1forverify = ComputeHMACSHA1(hmac1_verify_byte, hmac1pas_verify_byte);
                        if (data_hmac1[c_hmac1] == Convert.ToBase64String(hmac1forverify))
                        {
                            Console.WriteLine("\nMatch found\n\n");
                        }
                        else
                        {
                            Console.WriteLine("\n!!!!!!!!!!!!!!!");
                            Console.WriteLine("Dismatch");
                            Console.WriteLine("!!!!!!!!!!!!!!!\n\n");
                        }
                    }
                    else
                    {
                        Console.WriteLine("\n-------------------------------------------------");
                        Console.WriteLine("Done");
                        Console.WriteLine("-------------------------------------------------\n\n");
                    }
                    c_hmac1++;
                    Console.ReadLine();
                    break;
                case 2:
                    Console.WriteLine("Enter the message to find a hash via HMACSHA256:");
                    string hmac256_input = Console.ReadLine();
                    Console.WriteLine("Enter the password for your message:");
                    string hmac256pas_input = null;
                    while (true)
                    {
                        var key = Console.ReadKey(true);
                        if (key.Key == ConsoleKey.Enter)
                            break;
                        hmac256pas_input += key.KeyChar;
                    }
                    byte[] hmac256_byte = Encoding.Unicode.GetBytes(hmac256_input);
                    byte[] hmac256pas_byte = Encoding.Unicode.GetBytes(hmac256pas_input);
                    var hmac256forinput = ComputeHMACSHA1(hmac256_byte, hmac256pas_byte);
                    data_hmac256[c_hmac256] = Convert.ToBase64String(hmac256forinput);
                    Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    Console.WriteLine("Do you want to verify your message?");
                    Console.WriteLine("1 - yes");
                    Console.WriteLine("2 - no");
                    Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    string choice_2 = Console.ReadLine();
                    if (choice_2 == "yes")
                    {
                        Console.WriteLine("Enter your message:");
                        string hmac256_verify = Console.ReadLine();
                        Console.WriteLine("Enter the password for your message:");
                        string hmac256pas_verify = null;
                        while (true)
                        {
                            var key = Console.ReadKey(true);
                            if (key.Key == ConsoleKey.Enter)
                                break;
                            hmac256pas_verify += key.KeyChar;
                        }
                        byte[] hmac256_verify_byte = Encoding.Unicode.GetBytes(hmac256_verify);
                        byte[] hmac256pas_verify_byte = Encoding.Unicode.GetBytes(hmac256pas_verify);
                        var hmac256forverify = ComputeHMACSHA1(hmac256_verify_byte, hmac256pas_verify_byte);
                        if (data_hmac256[c_hmac256] == Convert.ToBase64String(hmac256forverify))
                        {
                            Console.WriteLine("\nMatch found\n\n");
                        }
                        else
                        {
                            Console.WriteLine("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                            Console.WriteLine("Dismatch");
                            Console.WriteLine("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n");
                        }
                    }
                    else
                    {
                        Console.WriteLine("\n-------------------------------------------------");
                        Console.WriteLine("Done");
                        Console.WriteLine("-------------------------------------------------\n\n");
                    }
                    c_hmac256++;
                    Console.ReadLine();
                    break;
                case 3:
                    Console.WriteLine("Enter the message to find a hash via HMACSHA512:");
                    string hmac512_input = Console.ReadLine();
                    Console.WriteLine("Enter the password for your message:");
                    string hmac512pas_input = null;
                    while (true)
                    {
                        var key = Console.ReadKey(true);
                        if (key.Key == ConsoleKey.Enter)
                            break;
                        hmac512pas_input += key.KeyChar;
                    }
                    byte[] hmac512_byte = Encoding.Unicode.GetBytes(hmac512_input);
                    byte[] hmac512pas_byte = Encoding.Unicode.GetBytes(hmac512pas_input);
                    var hmac512forinput = ComputeHMACSHA1(hmac512_byte, hmac512pas_byte);
                    data_hmac512[c_hmac512] = Convert.ToBase64String(hmac512forinput);
                    Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    Console.WriteLine("Do you want to verify your message?");
                    Console.WriteLine("1 - yes");
                    Console.WriteLine("2 - no");
                    Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    string choice_3 = Console.ReadLine();
                    if (choice_3 == "yes")
                    {
                        Console.WriteLine("Enter your message:");
                        string hmac512_verify = Console.ReadLine();
                        Console.WriteLine("Enter the password for your message:");
                        string hmac512pas_verify = null;
                        while (true)
                        {
                            var key = Console.ReadKey(true);
                            if (key.Key == ConsoleKey.Enter)
                                break;
                            hmac512pas_verify += key.KeyChar;
                        }
                        byte[] hmac512_verify_byte = Encoding.Unicode.GetBytes(hmac512_verify);
                        byte[] hmac512pas_verify_byte = Encoding.Unicode.GetBytes(hmac512pas_verify);
                        var hmac512forverify = ComputeHMACSHA1(hmac512_verify_byte, hmac512pas_verify_byte);
                        if (data_hmac512[c_hmac512] == Convert.ToBase64String(hmac512forverify))
                        {
                            Console.WriteLine("\nMatch found\n\n");
                        }
                        else
                        {
                            Console.WriteLine("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                            Console.WriteLine("Dismatch");
                            Console.WriteLine("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n");
                        }
                    }
                    else
                    {
                        Console.WriteLine("\n-------------------------------------------------");
                        Console.WriteLine("Done");
                        Console.WriteLine("-------------------------------------------------\n\n");
                    }
                    c_hmac512++;
                    Console.ReadLine();
                    break;
                case 4:
                    Console.WriteLine("Enter the message to find a hash via HMACMD5:");
                    string hmacmd5_input = Console.ReadLine();
                    Console.WriteLine("Enter the password for your message:");
                    string hmacmd5pas_input = null;
                    while (true)
                    {
                        var key = Console.ReadKey(true);
                        if (key.Key == ConsoleKey.Enter)
                            break;
                        hmacmd5pas_input += key.KeyChar;
                    }
                    byte[] hmacmd5_byte = Encoding.Unicode.GetBytes(hmacmd5_input);
                    byte[] hmacmd5pas_byte = Encoding.Unicode.GetBytes(hmacmd5pas_input);
                    var hmacmd5forinput = ComputeHMACSHA1(hmacmd5_byte, hmacmd5pas_byte);
                    data_hmacmd5[c_hmacmd5] = Convert.ToBase64String(hmacmd5forinput);
                    Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    Console.WriteLine("Do you want to verify your message?");
                    Console.WriteLine("1 - yes");
                    Console.WriteLine("2 - no");
                    Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    string choice_4 = Console.ReadLine();
                    if (choice_4 == "yes")
                    {
                        Console.WriteLine("Enter your message:");
                        string hmacmd5_verify = Console.ReadLine();
                        Console.WriteLine("Enter the password for your message:");
                        string hmacmd5pas_verify = null;
                        while (true)
                        {
                            var key = Console.ReadKey(true);
                            if (key.Key == ConsoleKey.Enter)
                                break;
                            hmacmd5pas_verify += key.KeyChar;
                        }
                        byte[] hmacmd5_verify_byte = Encoding.Unicode.GetBytes(hmacmd5_verify);
                        byte[] hmacmd5pas_verify_byte = Encoding.Unicode.GetBytes(hmacmd5pas_verify);
                        var hmacmd5forverify = ComputeHMACSHA1(hmacmd5_verify_byte, hmacmd5_verify_byte);
                        if (data_hmacmd5[c_hmacmd5] == Convert.ToBase64String(hmacmd5forverify))
                        {
                            Console.WriteLine("\nMatch found\n\n");
                        }
                        else
                        {
                            Console.WriteLine("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                            Console.WriteLine("Dismatch");
                            Console.WriteLine("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n");
                        }
                    }
                    else
                    {
                        Console.WriteLine("\n-------------------------------------------------");
                        Console.WriteLine("Done");
                        Console.WriteLine("-------------------------------------------------\n\n");
                    }
                    c_hmacmd5++;
                    Console.ReadLine();
                    break;
                case 5:
                    Environment.Exit(0);
                    break;
            }
        }
        while (true);
        

    }

    public static byte[] ComputeHMACSHA1(byte[] dataforhmac, byte[] pas)
    {
        byte[] key = new byte[dataforhmac.Length];
        for (int i = 0; i < key.Length; i++)
        {
            key[i] = pas[i % pas.Length];
        }
        using (var hmac1 = new HMACSHA1(key))
        {
            return hmac1.ComputeHash(dataforhmac);
        }
    }

    public static byte[] ComputeHMACSHA256(byte[] dataforhmac, byte[] pas)
    {
        byte[] key = new byte[dataforhmac.Length];
        for (int i = 0; i < key.Length; i++)
        {
            key[i] = pas[i % pas.Length];
        }
        using (var hmac256 = new HMACSHA256(key))
        {
            return hmac256.ComputeHash(dataforhmac);
        }
    }

    public static byte[] ComputeHMACSHA512(byte[] dataforhmac, byte[] pas)
    {
        byte[] key = new byte[dataforhmac.Length];
        for (int i = 0; i < key.Length; i++)
        {
            key[i] = pas[i % pas.Length];
        }
        using (var hmac512 = new HMACSHA512(key))
        {
            return hmac512.ComputeHash(dataforhmac);
        }
    }

    public static byte[] ComputeHMACMD5(byte[] dataforhmac, byte[] pas)
    {
        byte[] key = new byte[dataforhmac.Length];
        for (int i = 0; i < key.Length; i++)
        {
            key[i] = pas[i % pas.Length];
        }
        using (var hmacmd5 = new HMACMD5(key))
        {
            return hmacmd5.ComputeHash(dataforhmac);
        }
    }
}