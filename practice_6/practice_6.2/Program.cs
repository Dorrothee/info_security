using System.Security.Cryptography;
using System.Text;


class Assymetric_1
{
    static void Main()
    {
        do
        {
            Console.WriteLine("Want you to run program?" + "   YES / NO");
            Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            string choice = Console.ReadLine();
            Console.WriteLine();
            if (choice.ToLower() == "yes")
            {
                Console.WriteLine("Choose which algorithm for encryption you want to use:");
                Console.WriteLine("1 - DES");
                Console.WriteLine("2 - Triple-DES");
                Console.WriteLine("3 - AES");
                Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                int option = Convert.ToInt32(Console.ReadLine());
                Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                Console.WriteLine("Enter the text you want to hash:");
                string input = Console.ReadLine();
                Console.WriteLine("Enter the password for your text:");
                string password = null;
                while (true)
                {
                    var key = Console.ReadKey(true);
                    if (key.Key == ConsoleKey.Enter)
                        break;
                    password += key.KeyChar;
                }
                byte[] salt = GenerateRandomNumber(32);
                int iteration = 40000;
                byte[] hash = null;
                for (int i = 0; i < 10; i++)
                {
                    hash = PBKDF2.HashPassword(password, iteration, salt);
                    iteration += 50000;
                }
                Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
                SymmetricAlgorithm algo;
                switch (option)
                {
                    case 1:
                        var key_des = KeyInitializer(8, hash);
                        var iv_des = IvInitializer(8, hash);
                        algo = DESCryptoServiceProvider.Create();
                        var des = new Assymetric_Algos();
                        Console.WriteLine("------------------Realization via  DES------------------");
                        Console.WriteLine("Original text: " + input);
                        var encrypted_des = des.Symmetric_Encryption(Encoding.UTF8.GetBytes(input), key_des, iv_des, algo);
                        Console.WriteLine("Encrypted text: " + Convert.ToBase64String(encrypted_des));
                        var decrypted_des = des.Symmetric_Decryption(encrypted_des, key_des, iv_des, algo);
                        Console.WriteLine("Decrypted text: " + Encoding.UTF8.GetString(decrypted_des) + "\n");
                        break;
                    case 2:
                        var key_td = KeyInitializer(16, hash);
                        var iv_td = IvInitializer(8, hash);
                        algo = TripleDESCryptoServiceProvider.Create();
                        var td = new Assymetric_Algos();
                        Console.WriteLine("---------------Realization via Triple-Des---------------");
                        Console.WriteLine("Original text: " + input);
                        var encrypted_td = td.Symmetric_Encryption(Encoding.UTF8.GetBytes(input), key_td, iv_td, algo);
                        Console.WriteLine("Encrypted text: " + Convert.ToBase64String(encrypted_td));
                        var decrypted = td.Symmetric_Decryption(encrypted_td, key_td, iv_td, algo);
                        Console.WriteLine("Decrypted text: " + Encoding.UTF8.GetString(decrypted) + "\n");
                        break;
                    case 3:
                        var key_aes = KeyInitializer(32, hash);
                        var iv_aes = IvInitializer(16, hash);
                        algo = AesCryptoServiceProvider.Create();
                        var aes = new Assymetric_Algos();
                        Console.WriteLine("------------------Realization via  AES------------------");
                        Console.WriteLine("Original text: " + input);
                        var encrypted_aes = aes.Symmetric_Encryption(Encoding.UTF8.GetBytes(input), key_aes, iv_aes, algo);
                        Console.WriteLine("Encrypted text: " + Convert.ToBase64String(encrypted_aes));
                        var decrypted_aes = aes.Symmetric_Decryption(encrypted_aes, key_aes, iv_aes, algo);
                        Console.WriteLine("Decrypted text: " + Encoding.UTF8.GetString(decrypted_aes) + "\n");
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

    public static byte[] GenerateRandomNumber(int length)
    {
        using (var randomNumberGenerator = RandomNumberGenerator.Create())
        {
            var rnd = new byte[length];
            randomNumberGenerator.GetBytes(rnd);

            return rnd;
        }
    }

    public static byte[] KeyInitializer(int length, byte[] our_hash)
    {
        int l = length;
        var KEY = new byte[l];
        int key = 0;
        for (int i = 0; i < l; i++)
        {
            KEY[key] = our_hash[i];
            key++;
        }
        return KEY;
    }

    public static byte[] IvInitializer(int length, byte[] our_hash)
    {
        int l = length;
        var IV = new byte[l];
        int iv = 0;
        for (int i = our_hash.Length - 1; i != our_hash.Length - (l+1); i--)
        {
            IV[iv] = our_hash[i];
            iv++;
        }
        return IV;
    }
}


public class Assymetric_Algos
{
    public byte[] Symmetric_Encryption(byte[] toEncrypt, byte[] key, byte[] iv, SymmetricAlgorithm symmetricAlgorithm)
    {
        using (var sym = symmetricAlgorithm)
        {
            sym.Mode = CipherMode.CBC;
            sym.Padding = PaddingMode.PKCS7;
            sym.Key = key;
            sym.IV = iv;

            using (var memoryStream = new MemoryStream())
            {
                var cryptoStream = new CryptoStream(memoryStream, sym.CreateEncryptor(), CryptoStreamMode.Write);
                cryptoStream.Write(toEncrypt, 0, toEncrypt.Length);
                cryptoStream.FlushFinalBlock();

                return memoryStream.ToArray();
            }
        }
    }

    public byte[] Symmetric_Decryption(byte[] toDecrypt, byte[] key, byte[] iv, SymmetricAlgorithm symmetricAlgorithm)
    {
        using (var sym = symmetricAlgorithm)
        {
            sym.Mode = CipherMode.CBC;
            sym.Padding = PaddingMode.PKCS7;
            sym.Key = key;
            sym.IV = iv;

            using (var memoryStream = new MemoryStream())
            {
                var cryptoStream = new CryptoStream(memoryStream, sym.CreateDecryptor(), CryptoStreamMode.Write);
                cryptoStream.Write(toDecrypt, 0, toDecrypt.Length);
                cryptoStream.FlushFinalBlock();

                return memoryStream.ToArray();
            }
        }
    }
}

public class PBKDF2
{
    public static byte[] HashPassword(string passwordToHash, int numOfRounds, byte[] generated_salt)
    {
        var hashedPassword = PBKDF2.HashPasswordhash(Encoding.UTF8.GetBytes(passwordToHash), generated_salt, numOfRounds);
        return hashedPassword;
    }

    public static byte[] HashPasswordhash(byte[] toBeHashed, byte[] generated_salt, int numOfRounds)
    {
        using (var rfc2898 = new Rfc2898DeriveBytes(toBeHashed, generated_salt, numOfRounds, HashAlgorithmName.SHA256))
        {
            return rfc2898.GetBytes(32);
        }
    }
}