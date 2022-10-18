using System.Security.Cryptography;
using System.Text;
class HashProgram
{
    public static void Main()
    {
        int j = 0;
        string[] data_login = new string[10];
        string[] data_password = new string[10];
        string[] salt_login = new string[10];
        string[] salt_pas = new string[10];
        do
        {
            Console.WriteLine("Choose your option:");
            Console.WriteLine("1 - Create your personal office");
            Console.WriteLine("2 - To verify your data");
            Console.WriteLine("3 - Exit");
            Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            int option = Convert.ToInt32(Console.ReadLine());
            Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
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
                    byte[] salt_byte_login = HashAuthentication.GenerateSalt();
                    byte[] salt_byte_pas = HashAuthentication.GenerateSalt();
                    var hashedLogin = HashAuthentication.HashPassword(login_byte, salt_byte_login, numOfRounds);
                    var hashedPas = HashAuthentication.HashPassword(pas_byte, salt_byte_pas, numOfRounds);
                    data_login[j] = Convert.ToBase64String(hashedLogin);
                    data_password[j] = Convert.ToBase64String(hashedPas);
                    salt_login[j] = Convert.ToBase64String(salt_byte_login);
                    salt_pas[j] = Convert.ToBase64String(salt_byte_pas);
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
                    var forverifylogin = HashAuthentication.HashPassword(login_verify_byte, salt_byte_login, numOfRounds);
                    var forverifypas = HashAuthentication.HashPassword(pas_verify_byte, salt_byte_pas, numOfRounds);
                    int index_login = Array.IndexOf(data_login, Convert.ToBase64String(forverifylogin));
                    int index_pas = Array.IndexOf(data_password, Convert.ToBase64String(forverifypas));
                    if (data_login.Contains(Convert.ToBase64String(forverifylogin)) && data_password.Contains(Convert.ToBase64String(forverifypas)) && index_login == index_pas)
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
}


public class HashAuthentication
{
    public static byte[] GenerateSalt()
    {
        const int salt_length = 32;
        using (var randomNumberGenerator = RandomNumberGenerator.Create())
        {
            var rnd = new byte[salt_length];
            randomNumberGenerator.GetBytes(rnd);

            return rnd;
        }
    }

    public static byte[] HashPassword(byte[] toBeHashed, byte[] salt, int numOfRounds)
    {
        using (var rfc2898 = new Rfc2898DeriveBytes(toBeHashed, salt, numOfRounds))
        {
            return rfc2898.GetBytes(20);
        }
    }
}