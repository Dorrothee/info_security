using System.Security.Cryptography;
using System.Text;
class HashProgram
{
    public static void Main()
    {
        int j = 0;
        string[] data_login = new string[10];
        string[] data_password = new string[10];
        do
        {
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
                    Console.WriteLine("\n-----------------------------");
                    Console.WriteLine("Authentication\n");
                    Console.WriteLine("\n-----------------------------\n");
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
                    Console.WriteLine("\n...");
                    Console.WriteLine("Processing");
                    Console.WriteLine("\n...\n");
                    byte[] login_byte = Encoding.Unicode.GetBytes(login_input);
                    byte[] pas_byte = Encoding.Unicode.GetBytes(pas_input);
                    var hmac256forlogin = ComputeHMACSHA256(login_byte, pas_byte);
                    var hmac256forpas = ComputeHMACSHA256(pas_byte, login_byte);
                    data_login[j] = Convert.ToBase64String(hmac256forlogin);
                    data_password[j] = Convert.ToBase64String(hmac256forpas);
                    j++;
                    Console.WriteLine("\n\n-----------------------------");
                    Console.WriteLine("Done");
                    Console.ReadLine();
                    break;
                case 2:
                    Console.WriteLine("\n\n-----------------------------");
                    Console.WriteLine("Verification");
                    Console.WriteLine("\n\n-----------------------------");
                    Console.WriteLine("Enter your login:");
                    string login_verify = Console.ReadLine();
                    Console.WriteLine("Enter the password:");
                    string pas_verify = null;
                    while (true)
                    {
                        var key = Console.ReadKey(true);
                        if (key.Key == ConsoleKey.Enter)
                            break;
                        pas_verify += key.KeyChar;
                    }
                    byte[] login_verify_byte = Encoding.Unicode.GetBytes(login_verify);
                    byte[] pas_verify_byte = Encoding.Unicode.GetBytes(pas_verify);
                    var hmac256forverifylogin = ComputeHMACSHA256(login_verify_byte, pas_verify_byte);
                    var hmac256forverifypas = ComputeHMACSHA256(pas_verify_byte, login_verify_byte);
                    int index_login = Array.IndexOf(data_login, Convert.ToBase64String(hmac256forverifylogin));
                    int index_pas = Array.IndexOf(data_password, Convert.ToBase64String(hmac256forverifypas));
                    if (data_login.Contains(Convert.ToBase64String(hmac256forverifylogin)) && data_password.Contains(Convert.ToBase64String(hmac256forverifypas)) && index_login == index_pas)
                    {
                        Console.WriteLine("\n\n-----------------------------");
                        Console.WriteLine("Such user exists\n\n");
                        }
                    else
                    {
                        Console.WriteLine("\n\n-----------------------------");
                        Console.WriteLine("Such user does not exist\n\n");
                    }
                    break;
                    Console.ReadLine();
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