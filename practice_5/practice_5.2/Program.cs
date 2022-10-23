using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;


class PBKDF2_Hash
{
    static void Main()
    {
        do
        {
            Console.WriteLine("Want you to run program?" + "   YES / NO");
            Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            string choice = Console.ReadLine();
            Console.WriteLine();
            if (choice.ToLower()=="yes")
            {
                Console.WriteLine("Choose which method for hashing you want to use:");
                Console.WriteLine("1 - SHA1");
                Console.WriteLine("2 - SHA256");
                Console.WriteLine("3 - SHA384");
                Console.WriteLine("4 - SHA512");
                Console.WriteLine("5 - MD5");
                Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                int option = Convert.ToInt32(Console.ReadLine());
                Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                Console.WriteLine("Enter the password you want to hash:");
                string password = null;
                while (true)
                {
                    var key = Console.ReadKey(true);
                    if (key.Key == ConsoleKey.Enter)
                        break;
                    password += key.KeyChar;
                }
                int iteration = 40000;
                Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
                switch (option)
                {
                    case 1:
                        for (int i = 0; i < 10; i++)
                        {
                            HashPassword_1option(password, iteration);
                            iteration += 50000;
                        }
                        break;
                    case 2:
                        for (int i = 0; i < 10; i++)
                        {
                            HashPassword_2option(password, iteration);
                            iteration = iteration + 50000;
                        }
                        break;
                    case 3:
                        for (int i = 0; i < 10; i++)
                        {
                            HashPassword_3option(password, iteration);
                            iteration = iteration + 50000;
                        }
                        break;
                    case 4:
                        for (int i = 0; i < 10; i++)
                        {
                            HashPassword_4option(password, iteration);
                            iteration = iteration + 50000;
                        }
                        break;
                    case 5:
                        for (int i = 0; i < 10; i++)
                        {
                            HashPassword_5option(password, iteration);
                            iteration = iteration + 50000;
                        }
                        break;
                }
            }
            if (choice.ToLower() == "no")
            {
                break;
            }
            
        }
        while (true);
    }

    private static void HashPassword_1option(string passwordToHash, int numOfRounds)
    {
        var sw = new Stopwatch();
        sw.Start();
        var hashedPassword = PBKDF2.HashPasswordsha1(Encoding.UTF8.GetBytes(passwordToHash), PBKDF2.GenerateSalt(), numOfRounds);
        sw.Stop();
        Console.WriteLine("Password to hash:" + passwordToHash);
        Console.WriteLine("Hashed Password via sha1:" + Convert.ToBase64String(hashedPassword));
        Console.WriteLine("Iterations <" + numOfRounds + "> Elapsed Time: " + sw.ElapsedMilliseconds + "ms");
        Console.WriteLine();
    }

    private static void HashPassword_2option(string passwordToHash, int numOfRounds)
    {
        var sw = new Stopwatch();
        sw.Start();
        var hashedPassword = PBKDF2.HashPasswordsha256(Encoding.UTF8.GetBytes(passwordToHash), PBKDF2.GenerateSalt(), numOfRounds);
        sw.Stop();
        Console.WriteLine("Password to hash:" + passwordToHash);
        Console.WriteLine("Hashed Password via sha256:" + Convert.ToBase64String(hashedPassword));
        Console.WriteLine("Iterations <" + numOfRounds + "> Elapsed Time: " + sw.ElapsedMilliseconds + "ms");
        Console.WriteLine();
    }

    private static void HashPassword_3option(string passwordToHash, int numOfRounds)
    {
        var sw = new Stopwatch();
        sw.Start();
        var hashedPassword = PBKDF2.HashPasswordsha384(Encoding.UTF8.GetBytes(passwordToHash), PBKDF2.GenerateSalt(), numOfRounds);
        sw.Stop();
        Console.WriteLine("Password to hash:" + passwordToHash);
        Console.WriteLine("Hashed Password via384:" + Convert.ToBase64String(hashedPassword));
        Console.WriteLine("Iterations <" + numOfRounds + "> Elapsed Time: " + sw.ElapsedMilliseconds + "ms");
        Console.WriteLine();
    }

    private static void HashPassword_4option(string passwordToHash, int numOfRounds)
    {
        var sw = new Stopwatch();
        sw.Start();
        var hashedPassword = PBKDF2.HashPasswordsha512(Encoding.UTF8.GetBytes(passwordToHash), PBKDF2.GenerateSalt(), numOfRounds);
        sw.Stop();
        Console.WriteLine("Password to hash:" + passwordToHash);
        Console.WriteLine("Hashed Password via sha512:" + Convert.ToBase64String(hashedPassword));
        Console.WriteLine("Iterations <" + numOfRounds + "> Elapsed Time: " + sw.ElapsedMilliseconds + "ms");
        Console.WriteLine();
    }

    private static void HashPassword_5option(string passwordToHash, int numOfRounds)
    {
        var sw = new Stopwatch();
        sw.Start();
        var hashedPassword = PBKDF2.HashPasswordmd5(Encoding.UTF8.GetBytes(passwordToHash), PBKDF2.GenerateSalt(), numOfRounds);
        sw.Stop();
        Console.WriteLine("Password to hash:" + passwordToHash);
        Console.WriteLine("Hashed Password via md5:" + Convert.ToBase64String(hashedPassword));
        Console.WriteLine("Iterations <" + numOfRounds + "> Elapsed Time: " + sw.ElapsedMilliseconds + "ms");
        Console.WriteLine();
    }
}

public class PBKDF2
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

    public static byte[] HashPasswordsha1(byte[] toBeHashed, byte[] salt, int numOfRounds)
    {
        using (var rfc2898 = new Rfc2898DeriveBytes(toBeHashed, salt, numOfRounds))
        {
            return rfc2898.GetBytes(20);
        }
    }

    public static byte[] HashPasswordsha256(byte[] toBeHashed, byte[] salt, int numOfRounds)
    {
        using (var rfc2898 = new Rfc2898DeriveBytes(toBeHashed, salt, numOfRounds, HashAlgorithmName.SHA256))
        {
            return rfc2898.GetBytes(32);
        }
    }

    public static byte[] HashPasswordsha384(byte[] toBeHashed, byte[] salt, int numOfRounds)
    {
        using (var rfc2898 = new Rfc2898DeriveBytes(toBeHashed, salt, numOfRounds, HashAlgorithmName.SHA384))
        {
            return rfc2898.GetBytes(48);
        }
    }

    public static byte[] HashPasswordsha512(byte[] toBeHashed, byte[] salt, int numOfRounds)
    {
        using (var rfc2898 = new Rfc2898DeriveBytes(toBeHashed, salt, numOfRounds, HashAlgorithmName.SHA512))
        {
            return rfc2898.GetBytes(64);
        }
    }

    public static byte[] HashPasswordmd5(byte[] toBeHashed, byte[] salt, int numOfRounds)
    {
        using (var rfc2898 = new Rfc2898DeriveBytes(toBeHashed, salt, numOfRounds, HashAlgorithmName.MD5))
        {
            return rfc2898.GetBytes(16);
        }
    }
}