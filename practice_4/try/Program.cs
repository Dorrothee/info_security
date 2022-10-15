using System.Security.Cryptography;
using System.Text;
class HashProgram
{
    public static void Main()
    {
        do
        {
            string data = "";
            Console.WriteLine("Choose your option:");
            Console.WriteLine("1 - Create your personal office");
            Console.WriteLine("2 - To verify your data");
            Console.WriteLine("3 - Exit");
            Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            int option = Convert.ToInt32(Console.ReadLine());
            Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            switch (option)
            {
                case 1:
                    Console.WriteLine("Authentication\n");
                    Console.WriteLine("Enter your login:");
                    string login_input = Console.ReadLine();
                    Console.WriteLine("Enter your password:");
                    string pas_input = null;
                    while (true)
                    {
                        var key = Console.ReadKey(true);
                        if (key.Key == ConsoleKey.Enter)
                            break;
                        pas_input += key.KeyChar;
                    }
                    Console.WriteLine("\n\n-----------------------------");
                    Console.WriteLine("Processing");
                    byte[] login_byte = Encoding.Unicode.GetBytes(login_input);
                    byte[] pas_byte = Encoding.Unicode.GetBytes(pas_input);
                    var hmac256forinput = ComputeHMACSHA256(login_byte, pas_byte);
                    data = data + Convert.ToBase64String(hmac256forinput) + " ";
                    Console.WriteLine("\n\n-----------------------------");
                    Console.WriteLine("Done");
                    break;
                case 2:
                    Console.WriteLine("Enter your login:");
                    string login_verify = Console.ReadLine();
                    Console.WriteLine("Enter the password:");
                    string pas_verify = Console.ReadLine();
                    byte[] login_verify_byte = Encoding.Unicode.GetBytes(login_verify);
                    byte[] pas_verify_byte = Encoding.Unicode.GetBytes(pas_verify);
                    var hmac256forverify = ComputeHMACSHA256(login_verify_byte, pas_verify_byte);
                    
                    if (data.Contains(Convert.ToBase64String(hmac256forverify)))
                    {
                        Console.WriteLine("\n\n-----------------------------");
                        Console.WriteLine("Such user exists");
                    }
                    else
                    {
                        Console.WriteLine("Such user does not exist");
                    }
                    break;
                case 3:
                    Environment.Exit(0);
                    break;
                default:
                    Console.WriteLine("Choose an option from the list above");
                    break;
            }
        }
        while (true);
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
}