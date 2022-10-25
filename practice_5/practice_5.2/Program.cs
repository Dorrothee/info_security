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
                HashAlgorithmName hashAlgorithmName;
                switch (option)
                {
                    case 1:
                        hashAlgorithmName = HashAlgorithmName.SHA1;
                        for (int i = 0; i < 10; i++)
                        {
                            PBKDF2.HashPassword(password, iteration, hashAlgorithmName);
                            iteration += 50000;
                        }
                        break;
                    case 2:
                        hashAlgorithmName = HashAlgorithmName.SHA256;
                        for (int i = 0; i < 10; i++)
                        {
                            PBKDF2.HashPassword(password, iteration, hashAlgorithmName);
                            iteration = iteration + 50000;
                        }
                        break;
                    case 3:
                        hashAlgorithmName = HashAlgorithmName.SHA384;
                        for (int i = 0; i < 10; i++)
                        {
                            PBKDF2.HashPassword(password, iteration, hashAlgorithmName);
                            iteration = iteration + 50000;
                        }
                        break;
                    case 4:
                        hashAlgorithmName = HashAlgorithmName.SHA512;
                        for (int i = 0; i < 10; i++)
                        {
                            PBKDF2.HashPassword(password, iteration, hashAlgorithmName);
                            iteration = iteration + 50000;
                        }
                        break;
                    case 5:
                        hashAlgorithmName = HashAlgorithmName.MD5;
                        for (int i = 0; i < 10; i++)
                        {
                            PBKDF2.HashPassword(password, iteration, hashAlgorithmName);
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

    public static void HashPassword(string passwordToHash, int numOfRounds, HashAlgorithmName hashalgorithmname)
    {
        var sw = new Stopwatch();
        sw.Start();
        var hashedPassword = PBKDF2.HashPasswordhash(Encoding.UTF8.GetBytes(passwordToHash), PBKDF2.GenerateSalt(), numOfRounds, hashalgorithmname);
        sw.Stop();
        Console.WriteLine("Password to hash:" + passwordToHash);
        Console.WriteLine("Hashed Password via " + hashalgorithmname + " :" + Convert.ToBase64String(hashedPassword));
        Console.WriteLine("Iterations <" + numOfRounds + "> Elapsed Time: " + sw.ElapsedMilliseconds + "ms");
        Console.WriteLine();
    }

    public static byte[] HashPasswordhash(byte[] toBeHashed, byte[] salt, int numOfRounds, HashAlgorithmName hashalgorithm)
    {
        using (var rfc2898 = new Rfc2898DeriveBytes(toBeHashed, salt, numOfRounds, hashalgorithm))
        {
            int size = 0;
            if (hashalgorithm == HashAlgorithmName.SHA1)
            {
                size = 20;
            }
            if (hashalgorithm == HashAlgorithmName.SHA256)
            {
                size = 32;
            }
            if (hashalgorithm == HashAlgorithmName.SHA384)
            {
                size = 48;
            }
            if (hashalgorithm == HashAlgorithmName.SHA512)
            {
                size = 64;
            }
            if (hashalgorithm == HashAlgorithmName.MD5)
            {
                size = 16;
            }

            return rfc2898.GetBytes(size);
        }
    }
}