using System;
using System.Security.Cryptography;
using System.Text;

class ECP
{
    static void Main()
    {
        using SHA256 alg = SHA256.Create();

        string key_path = @"C:\info_security\practice_9-10\practice_9-10\";
        string key_ext = "xml";
        string key_file;
        string our_path;

        var ds = new DigitalSignature();
        Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        try
        {
            Console.WriteLine("Enter the name of the file to save your key: ");
            key_file = Console.ReadLine();
            if (key_file == "")
            {
                Console.WriteLine("Please enter the name of the file first");
            }
            else
            {
                key_file = key_file.ToLower();
                our_path = key_path + key_file + key_ext;

                Console.WriteLine("Enter the message you want to sign:");
                string input = Console.ReadLine();

                byte[] input_bytes = Encoding.UTF8.GetBytes(input);
                byte[] datahash = alg.ComputeHash(input_bytes);

                ds.GenerateKeys(our_path);
                var signature = ds.Signdata(datahash);
                var verified = ds.VerifySignature(our_path, datahash, signature);
                Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                Console.WriteLine("\nOriginal Text = " + Encoding.Default.GetString(input_bytes));
                Console.WriteLine("\nDigital Signature = " + Convert.ToBase64String(signature));
                Console.WriteLine("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                Console.WriteLine(verified ? "The digital signature has been correctly verified." : "The digital signature has NOT been correctly verified.");

            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }
}

class DigitalSignature
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

    public byte[] Signdata(byte[] data)
    {
        var cspParameters = new CspParameters
        {
            KeyContainerName = containerName,
            Flags = CspProviderFlags.UseMachineKeyStore,
        };

        using (var rsa = new RSACryptoServiceProvider(2048, cspParameters))
        {
            rsa.PersistKeyInCsp = false;
            var rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);
            rsaFormatter.SetHashAlgorithm(nameof(SHA256));
            return rsaFormatter.CreateSignature(data);
        }
    }

    public bool VerifySignature(string publicKeyPath, byte[] data, byte[] signature)
    {
        using (var rsa = new RSACryptoServiceProvider(2048))
        {
            rsa.PersistKeyInCsp = false;
            rsa.FromXmlString(File.ReadAllText(publicKeyPath));
            var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
            rsaDeformatter.SetHashAlgorithm(nameof(SHA256));

            return rsaDeformatter.VerifySignature(data, signature);
        }
    }

}