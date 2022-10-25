using System.Security.Cryptography;
using System.Text;
class HashProgram
{
    public static void Main()
    {
        int j = 0;
        string[] data_login = new string[10];
        string[] data_password = new string[10];
        string[] data_salt = new string[10];
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
                    Console.WriteLine("Authentication");
                    Console.WriteLine("-----------------------------\n\n");
                    Console.WriteLine("Enter your login:");
                    string login_input = Console.ReadLine();
                    byte[] login_repeat = Encoding.UTF8.GetBytes(login_input);
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
                    Console.WriteLine("...\n");
                    byte[] login_byte = Encoding.Unicode.GetBytes(login_input);
                    byte[] salt = GenerateSalt();
                    string SALT = Convert.ToBase64String(salt);
                    string hashing = "";
                    int iteration = 40000;
                    for (int i = 0; i < 10; i++)
                    {
                        hashing = HashingPassword(pas_input, SALT, iteration);
                        iteration += 50000;
                    }
                    data_login[j] = Convert.ToBase64String(login_byte);
                    data_password[j] = hashing;
                    data_salt[j] = SALT;
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

                    int index_login = Array.IndexOf(data_login, Convert.ToBase64String(login_verify_byte));
                    string salt_verify = data_salt[index_login];
                    string hashing_verify = "";
                    int iteration_verify = 40000;
                    for (int i = 0; i < 10; i++)
                    {
                        hashing_verify = HashingPassword(pas_verify, salt_verify, iteration_verify);
                        iteration_verify += 50000;
                    }
                    if (data_password.Contains(hashing_verify))
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

    private static string HashingPassword(string passwordToHash, string salt, int numOfRounds)
    {
        byte[] salt_byte = Encoding.UTF8.GetBytes(salt);
        var hashedPassword = HashAuthentication.HashPassword(Encoding.UTF8.GetBytes(passwordToHash), salt_byte, numOfRounds);
        return Convert.ToBase64String(hashedPassword);
    }

}

public class HashAuthentication
{
    public static byte[] HashPassword(byte[] toBeHashed, byte[] salt, int numOfRounds)
    {
        using (var rfc2898 = new Rfc2898DeriveBytes(toBeHashed, salt, numOfRounds))
        {
            return rfc2898.GetBytes(20);
        }
    }
}