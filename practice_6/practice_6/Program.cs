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
                Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
                SymmetricAlgorithm algo;
                switch (option)
                {
                    case 1:
                        algo = DESCryptoServiceProvider.Create();
                        var des = new Assymetric_Algos();
                        var key_des = GenerateRandomNumber(8);
                        var iv_des = GenerateRandomNumber(8);
                        Console.WriteLine("------------------Realization via  DES------------------");
                        Console.WriteLine("Original text: " + input);
                        var encrypted_des = des.Symmetric_Encryption(Encoding.UTF8.GetBytes(input), key_des, iv_des, algo);
                        Console.WriteLine("Encrypted text: " + Convert.ToBase64String(encrypted_des));
                        var decrypted_des = des.Symmetric_Decryption(encrypted_des, key_des, iv_des, algo);
                        Console.WriteLine("Decrypted text: " + Encoding.UTF8.GetString(decrypted_des) + "\n");
                        break;
                    case 2:
                        algo = TripleDESCryptoServiceProvider.Create();
                        var td = new Assymetric_Algos();
                        var key_td = GenerateRandomNumber(16);
                        var iv_td = GenerateRandomNumber(8);
                        Console.WriteLine("---------------Realization via Triple-Des---------------");
                        Console.WriteLine("Original text: " + input);
                        var encrypted_td = td.Symmetric_Encryption(Encoding.UTF8.GetBytes(input), key_td, iv_td, algo);
                        Console.WriteLine("Encrypted text: " + Convert.ToBase64String(encrypted_td));
                        var decrypted = td.Symmetric_Decryption(encrypted_td, key_td, iv_td, algo);
                        Console.WriteLine("Decrypted text: " + Encoding.UTF8.GetString(decrypted) + "\n");
                        break;
                    case 3:
                        algo = AesCryptoServiceProvider.Create();
                        var aes = new Assymetric_Algos();
                        var key_aes = GenerateRandomNumber(32);
                        var iv_aes = GenerateRandomNumber(16);
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