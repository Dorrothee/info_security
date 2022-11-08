using System;
using System.Security.Cryptography;
using System.Text;

class Asymmetric_1
{
    static void Main()
    {
        var methodrsa = new AsymmetricMethods();
        Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        Console.WriteLine("Enter the text you want to handle with:");
        string input = Console.ReadLine();
        Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
        byte[] byte_input = Encoding.UTF8.GetBytes(input);
        methodrsa.AssignKey();
        var encrypted = methodrsa.Encryption(byte_input);
        var decrypted = methodrsa.Decryption(encrypted);
        Console.WriteLine("-----------------RSA Realization-----------------");
        Console.WriteLine("Your message: " + input);
        Console.WriteLine("Encrypted message: " + Convert.ToBase64String(encrypted));
        Console.WriteLine("Decrypted message: " + Encoding.UTF8.GetString(decrypted));
        Console.WriteLine("--------------------------------------------------");
    }
}

public class AsymmetricMethods
{
    private RSAParameters _publicKey, _privateKey;
    public void AssignKey()
    {
        using (var rsa = new RSACryptoServiceProvider(2048))
        {
            rsa.PersistKeyInCsp = false;
            _publicKey = rsa.ExportParameters(false);
            _privateKey = rsa.ExportParameters(true);
        }
    }
    public byte[] Encryption(byte[] toEncrypt)
    {
        byte[] cypher;
        using (var rsa = new RSACryptoServiceProvider())
        {
            rsa.PersistKeyInCsp = false;
            rsa.ImportParameters(_publicKey);
            cypher = rsa.Encrypt(toEncrypt, true);
        }
        return cypher;
    }
    public byte[] Decryption(byte[] toDecrypt)
    {
        byte[] decypher;
        using (var rsa = new RSACryptoServiceProvider())
        {
            rsa.PersistKeyInCsp = false;
            rsa.ImportParameters(_privateKey);
            decypher = rsa.Decrypt(toDecrypt, true);
        }
        return decypher;
    }
}