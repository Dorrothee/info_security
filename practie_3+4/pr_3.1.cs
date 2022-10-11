using System.Security.Cryptography;
using System.Text;
class HashProgram
{
    public static void Main()
    {
        Console.WriteLine("List of options you can do:");
        Console.WriteLine("1 - find hash using MD5");
        Console.WriteLine("2 - find hash using SHA");
        Console.WriteLine("3 - find hash via HMAC");
        Console.WriteLine("Choose what you want to do:");
        int option = Convert.ToInt32(Console.ReadLine());
        Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        switch(option)
        {
            case 1:
                Console.WriteLine("Enter the message to find a hash using MD5:");
                string md5_input = Console.ReadLine();
                Console.WriteLine("\n");
                var md5forinput = ComputeHashMD5(Encoding.Unicode.GetBytes(md5_input));
                Guid guidformd5input= new Guid(md5forinput);
                Console.WriteLine($"Your message: {md5_input}\n");
                Console.WriteLine($"Hash MD5: {Convert.ToBase64String(md5forinput)}");
                Console.WriteLine($"Guid: {guidformd5input}");
                break;
            case 2:
                Console.WriteLine("Enter the message to find a hash using SHA:");
                string sha_input = Console.ReadLine();
                Console.WriteLine("\n");
                var shaforinput = ComputeHashSHA256(Encoding.Unicode.GetBytes(sha_input));
                Console.WriteLine($"Your message: {sha_input}\n");
                Console.WriteLine($"Hash SHA: {Convert.ToBase64String(shaforinput)}");
                break;
            case 3:
                Console.WriteLine("Enter the message to find a hash via HMAC:");
                string hmac_input = Console.ReadLine();
                Console.WriteLine("Enter the password for a your message:");
                string hmacpas_input = Console.ReadLine();
                byte[] hmac_byte = Encoding.Unicode.GetBytes(hmac_input);
                byte[] hmacpas_byte = Encoding.Unicode.GetBytes(hmacpas_input);
                var hmac1forinput = ComputeHMACSHA1(hmac_byte, hmacpas_byte);
                var hmac256forinput = ComputeHMACSHA256(hmac_byte, hmacpas_byte);
                var hmac512forinput = ComputeHMACSHA512(hmac_byte, hmacpas_byte);
                var hmacmd5forinput = ComputeHMACMD5(hmac_byte, hmacpas_byte);
                Console.WriteLine($"\nYour message: {hmac_input}\n");
                Console.WriteLine($"Hash via HMAC1: {Convert.ToBase64String(hmac1forinput)}");
                Console.WriteLine($"Hash via HMAC256: {Convert.ToBase64String(hmac256forinput)}");
                Console.WriteLine($"Hash via HMAC512: {Convert.ToBase64String(hmac512forinput)}");
                Console.WriteLine($"Hash via HMACMD5: {Convert.ToBase64String(hmacmd5forinput)}");
                break;
            default:
                Console.WriteLine("Choose an option from the list above");
                break;
        }

    }

    static byte[] ComputeHashMD5(byte[] dataforMD5)
    {
        using (var md5 = MD5.Create())
        {
            return md5.ComputeHash(dataforMD5);
        }
    }

    public static byte[] ComputeHashSHA256(byte[] dataforSHA)
    {
        using (var sha256 = SHA256.Create())
        {
            return sha256.ComputeHash(dataforSHA);
        }
    }

    public static byte[] ComputeHMACSHA1(byte[]dataforhmac, byte[]pas)
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