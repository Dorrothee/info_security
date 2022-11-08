using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Collections.Immutable;

class Asymmetric_2
{
    static void Main()
    {
        string publicKey_Path = @"C:\info_security\practice_7\practice_7.2\key_folder\";
        string cypher_Path = @"C:\info_security\practice_7\practice_7.2\enc_folder\";
        string enc_Path = @"C:\info_security\practice_7\practice_7.2\enc_folder\";
        string surName;
        string our_path;
        string key_ext = ".xml";
        string enc_ext = ".txt";
        do
        {
            Console.WriteLine("Want you to run program?" + "   YES / NO");
            Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            string choice = Console.ReadLine();
            Console.WriteLine();
            var methodrsa = new AsymmetricMethods();
            Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            if (choice.ToLower() == "yes")
            {
                Console.WriteLine("Choose what you want to do in this program:");
                Console.WriteLine("1 - Generate keys and save the public one");
                Console.WriteLine("2 - Delete keys");
                Console.WriteLine("3 - Encrypt message");
                Console.WriteLine("4 - Decrypt message");
                Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                int option = Convert.ToInt32(Console.ReadLine());
                switch (option)
                {
                    case 1:
                        Console.WriteLine("Enter your surname in Ukrainian to create a file for your keys: ");
                        surName = Console.ReadLine();
                        if (surName == "")
                        {
                            Console.WriteLine("Please enter your surname first");
                        }
                        else
                        {
                            surName = surName.ToLower();
                            var surname = string.Concat(surName.Select(c => literation[c]));
                            surname = char.ToUpper(surname[0]) + surname.Substring(1);
                            our_path = publicKey_Path + surname + key_ext;
                            methodrsa.GenerateKeys(our_path);
                            Console.WriteLine("Generation completed..");
                        }
                        break;
                    case 2:
                        try
                        {
                            Console.Write("Write your surname: ");
                            surName = Console.ReadLine();
                            if (surName == "")
                            {
                                Console.WriteLine("Please enter your surname first");
                            }
                            else
                            {
                                surName = surName.ToLower();
                                var surname = string.Concat(surName.Select(c => literation[c]));
                                surname = char.ToUpper(surname[0]) + surname.Substring(1);
                                our_path = publicKey_Path + surname + key_ext;
                                methodrsa.DeleteKeys(our_path);
                                Console.WriteLine("Deletion completed..");
                            }
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e);
                            throw;
                        }
                        break;
                    case 3:
                        try
                        {
                            var files = Directory.GetFiles(publicKey_Path);
                            if (files.Length != 0)
                            {
                                Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                                Console.WriteLine("Enter the message you want to handle with:");
                                string input = Console.ReadLine();
                                Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                                Console.WriteLine("Enter the name for your file:");
                                string name = Console.ReadLine();
                                cypher_Path = cypher_Path + name + enc_ext;

                                Console.WriteLine("Public keys:");
                                for (int i = 0; i < files.Length; i++)
                                {
                                    Console.WriteLine((i + 1) + ". " + files[i]);
                                }

                                Console.Write("\nChoose public key file to use for encryption: ");
                                int num = Convert.ToInt32(Console.ReadLine());
                                our_path = files[num - 1];
                                byte[] encrypted = methodrsa.Encryption(our_path, Encoding.UTF8.GetBytes(input));
                                File.WriteAllBytes(cypher_Path, encrypted);
                                Console.WriteLine("Encryption completed");
                            }
                            else
                            {
                                Console.WriteLine("Public key folder is empty");
                            }
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e);
                            throw;
                        }
                        break;
                    case 4:
                        try
                        {
                            var files = Directory.GetFiles(enc_Path);
                            if (files.Length != 0)
                            {
                                Console.WriteLine("Encrypted file to chose from:");
                                for (int i = 0; i < files.Length; i++)
                                {
                                    Console.WriteLine((i + 1) + ". " + files[i]);
                                }

                                Console.Write("\nChoose which file you want to decrypt: ");
                                int pos = Convert.ToInt32(Console.ReadLine());
                                our_path = files[pos - 1];
                                Console.WriteLine(our_path);
                                byte[] original = methodrsa.Decryption(our_path);

                                Console.WriteLine("Original content: " + Encoding.UTF8.GetString(original));
                            }
                            else
                            {
                                Console.WriteLine("Empty folder");
                            }
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e);
                            throw;
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

    private static readonly ImmutableDictionary<char, string> literation = new Dictionary<char, string>
    {
            { 'а', "a" },
            { 'б', "b" },
            { 'в', "v" },
            { 'г', "g" },
            { 'ґ', "g" },
            { 'д', "d" },
            { 'е', "e" },
            { 'є', "ye" },
            { 'ж', "zh" },
            { 'з', "z" },
            { 'и', "y" },
            { '?', "i" },
            { 'ї', "yi" },
            { 'й', "y" },
            { 'к', "k" },
            { 'л', "l" },
            { 'м', "m" },
            { 'н', "n" },
            { 'о', "o" },
            { 'п', "p" },
            { 'р', "r" },
            { 'с', "s" },
            { 'т', "t" },
            { 'у', "u" },
            { 'ф', "f" },
            { 'х', "kh" },
            { 'ц', "ts" },
            { 'ч', "ch" },
            { 'ш', "sh" },
            { 'щ', "shch" },
            { 'ь', "'" },
            { 'ю', "yu" },
            { 'я', "ya" },
    }.ToImmutableDictionary();
}

public class AsymmetricMethods
{
    const string containerName = "RSAContainer";

    public void GenerateKeys(string publicKeyPath)
    {
        CspParameters cspParameters = new CspParameters(1)
        {
            KeyContainerName = containerName,
            Flags = CspProviderFlags.UseMachineKeyStore,
            ProviderName = "Microsoft Strong Cryptographic Provider",
        };
        using (var rsa = new RSACryptoServiceProvider(2048, cspParameters))
        {
            rsa.PersistKeyInCsp = true;
            File.WriteAllText(publicKeyPath, rsa.ToXmlString(false));
        }
    }

    public void DeleteKeys(string publicKeyPath)
    {
        CspParameters cspParameters = new CspParameters
        {
            KeyContainerName = containerName,
            Flags = CspProviderFlags.UseMachineKeyStore
        };
        var rsa = new RSACryptoServiceProvider(cspParameters)
        {
            PersistKeyInCsp = false
        };
        File.Delete(publicKeyPath);
        rsa.Clear();
    }

    public byte[] Encryption(string publickey_path, byte[] toEncrypt)
    {
        byte[] cypher;
        using (var rsa = new RSACryptoServiceProvider(2048))
        {
            rsa.PersistKeyInCsp = false;
            rsa.FromXmlString(File.ReadAllText(publickey_path));
            cypher = rsa.Encrypt(toEncrypt, true);
        }
        return cypher;
    }
    public byte[] Decryption(string cypher_path)
    {
        byte[] cypher_bytes = File.ReadAllBytes(cypher_path);
        byte[] decypher;
        var cspParams = new CspParameters
        {
            KeyContainerName = containerName,
            Flags = CspProviderFlags.UseMachineKeyStore
        };
        using (var rsa = new RSACryptoServiceProvider(2048, cspParams))
        {
            rsa.PersistKeyInCsp = true;
            decypher = rsa.Decrypt(cypher_bytes, true);
        }
        return decypher;
    }
}