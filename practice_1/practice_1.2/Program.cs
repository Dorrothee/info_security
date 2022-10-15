using System.Security.Cryptography;


class Random_Crypto
{
    public static void Main()
    {
        int c = 1;
        Console.WriteLine("Enter how many numbers you want to generate:");
        int am = Convert.ToInt32(Console.ReadLine());

        Console.WriteLine("Random generated secured number sequence:");

        for (int i = 0; i < am; i++)
        {
            var rnd = GenerateRandomNumber();
            //Console.WriteLine(c + ".");
            Console.WriteLine(Convert.ToBase64String(rnd));
            c++;
        }
        Console.ReadLine();
    }

    public static byte[] GenerateRandomNumber()
    {
        using (var randomNumberGenerator = RandomNumberGenerator.Create())
        {
            int bit = 64;
            var randomNumber = new byte[bit];
            randomNumberGenerator.GetBytes(randomNumber);
            return randomNumber;
        }
    }
}