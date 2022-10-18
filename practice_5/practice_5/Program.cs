using System.Security.Cryptography;
using System.Text;

class Salted_Hash
{
    static void Main()
    {
        Console.WriteLine("Enter your password:");
        string password = Console.ReadLine();
        Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
        byte[] salt = SaltedHash.GenerateSalt();
        Console.WriteLine("Password: " + password);
        Console.WriteLine("Salt: " + Convert.ToBase64String(salt));
        Console.WriteLine("---------------------------------------------------------------");
        var hashedPassword = SaltedHash.HashingviaSalt(Encoding.UTF8.GetBytes(password), salt);
        Console.WriteLine("Hashed Password: " + Convert.ToBase64String(hashedPassword));
        Console.ReadLine();
    }
}

public class SaltedHash
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

    private static byte[] Combine(byte[] pas, byte[] salt)
    {
        var unit = new byte[pas.Length + salt.Length];
        Buffer.BlockCopy(pas, 0, unit, 0, pas.Length);
        Buffer.BlockCopy(salt, 0, unit, pas.Length, salt.Length);

        return unit;
    }

    public static byte[] HashingviaSalt(byte[] toBeHashed, byte[] salting)
    {
        using (var sha256 = SHA256.Create())
        {
            return sha256.ComputeHash(Combine(toBeHashed, salting));
        }
    }
}

