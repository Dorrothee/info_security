using System;

public class Program_Random
{
    public static void Main()
    {
        Console.WriteLine("Enter the seed number: ");
        int seed = Convert.ToInt32(Console.ReadLine());

        Console.WriteLine("Enter how many numbers you want to generate:");
        int am = Convert.ToInt32(Console.ReadLine());

        Console.WriteLine("Enter the min number of range:");
        int min = Convert.ToInt32(Console.ReadLine());

        Console.WriteLine("Enter the max number of range:");
        int max = Convert.ToInt32(Console.ReadLine());

        if (max > min)
        {
            int c = 1;
            Random rnd = new Random(seed);
            Console.WriteLine("Random generated number sequence:");
            for (int i = 0; i < am; i++)
            {
                Console.WriteLine("{0,3}", c + ". " + rnd.Next(min, max)); //{0,3} -> format
                c++;
            }
        }
        else
        {
            Console.WriteLine("{0,9}", "!!!");
            Console.WriteLine("You've entered wrong range number. Try again");
        }
        Console.ReadLine();
    }
}