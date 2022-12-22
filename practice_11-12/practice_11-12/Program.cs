using System;
using System.Text;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;


class Authorization
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
                Console.WriteLine("- Admin");
                Console.WriteLine("- Finance");
                Console.WriteLine("- IT");
                Console.WriteLine("- Safety\n");
                Console.Write("Enter your role in the community: ");
                string role = Console.ReadLine();
                string[] model = new[] { role.ToLower() };
                Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
                Console.Write("Enter your login -> ");
                string username = Console.ReadLine();
                Console.Write("Enter your password -> ");
                string password = null;
                while (true)
                {
                    var key = Console.ReadKey(true);
                    if (key.Key == ConsoleKey.Enter)
                        break;
                    password += key.KeyChar;
                }
                Console.WriteLine("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
                Protector.Register(username, password, model);
                Console.WriteLine("Authentication");
                Console.Write("\nConfirm your login -> ");
                string username_a = Console.ReadLine();
                Console.Write("Confirm your password -> ");
                string password_a = null;
                while (true)
                {
                    var key_a = Console.ReadKey(true);
                    if (key_a.Key == ConsoleKey.Enter)
                        break;
                    password_a += key_a.KeyChar;
                }
                Console.WriteLine("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                Protector.LogIn(username_a, password_a);
                
                if(!Protector.CheckPassword(username_a, password_a))
                {
                    break;
                }

                Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                Console.WriteLine("\nList of actions community is responsible for:");
                Console.WriteLine("1 - Find a long-term strategic planning");
                Console.WriteLine("2 - Find projections of profit/loss");
                Console.WriteLine("3 - Find on-hand technical support");
                Console.WriteLine("4 - Find documents with all regulations");
                Console.Write("\nWhat do you want to have an access to: ");
                int option = Convert.ToInt32(Console.ReadLine());
                Role.Check(option);
            }
            Console.WriteLine();
            if (choice.ToLower() == "no")
            {
                break;
            }
        }
        while (true);
    }

    public class User
    {
        public string Login;
        public string PasswordHash;
        public byte[] Salt;
        public string[] Roles;

        public User(string login, string passwordhash, byte[] salt, string[] roles = null)
        {
            Login = login;
            PasswordHash = passwordhash;
            Salt = salt;
            Roles = roles;
        }
    }

    public class Hashing
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

        public static byte[] HashPassword(string passwordToHash, int numOfRounds, byte[] gensalt)
        {
            var hashedPassword = HashPasswordhash(Encoding.UTF8.GetBytes(passwordToHash), gensalt, numOfRounds);
            return hashedPassword;
        }

        public static byte[] HashPasswordhash(byte[] toBeHashed, byte[] salt, int numOfRounds)
        {
            using (var rfc2898 = new Rfc2898DeriveBytes(toBeHashed, salt, numOfRounds, HashAlgorithmName.SHA256))
            {
                return rfc2898.GetBytes(32);
            }
        }
    }

    public class Protector
    {
        private static Dictionary<string, User> _users = new Dictionary<string, User>();

        public static User Register(string login, string password, string[] roles)
        {
            if (Iftherename(login, out User existed))
            {
                Console.WriteLine("\n!!! Such user is already exists !!!\n\n");
                Console.WriteLine("Enter another login and password");
                Console.Write("Enter new login -> ");
                string newname = Console.ReadLine();
                Console.Write("Enter new password -> ");
                string newpas = null;
                while (true)
                {
                    var key = Console.ReadKey(true);
                    if (key.Key == ConsoleKey.Enter)
                        break;
                    newpas += key.KeyChar;
                }
                Console.WriteLine();
                byte[] salt = Hashing.GenerateSalt();
                byte[] hashpas = Hashing.HashPassword(newpas, 10, salt);
                string strnewpas = Convert.ToBase64String(hashpas);
                User users = new User(newname, strnewpas, salt, roles);
                _users.Add(newname, users);

                return existed;
            }
            else
            {
                byte[] salt = Hashing.GenerateSalt();
                byte[] hashpas = Hashing.HashPassword(password, 10, salt);
                string strhashpas = Convert.ToBase64String(hashpas);
                User users = new User(login, strhashpas, salt, roles);
                _users.Add(login, users);

                return users;
            }
        }
        public static bool CheckPassword(string login, string passwordtocompare)
        {
            if (!Iftherename(login, out User user))
            {
                Console.WriteLine("No match");
                return false;
            }
            byte[] salttocompare = user.Salt;
            var hashtocompare = Hashing.HashPassword(passwordtocompare, 10, salttocompare);
            string comparehash = Convert.ToBase64String(hashtocompare);
            if (Equals(comparehash, user.PasswordHash))
            {
                Console.WriteLine("Authentication was succeed");
                return true;
            }
            else
            {
                Console.WriteLine("Authentication was NOT succeed");
                return false;
            }
        }

        private static bool Iftherename(string userdata, out User data) => _users.TryGetValue(userdata, out data);

        public static void LogIn(string userName, string password)
        {
            if (CheckPassword(userName, password))
            {
                var identity = new GenericIdentity(userName, "OIBAuth");
                var principal = new GenericPrincipal(identity, _users[userName].Roles);
                Thread.CurrentPrincipal = principal;
            }
        }
    }

    public class Role
    {
        public static void OnlyForAdmins()
        {
            if (Thread.CurrentPrincipal == null)
            {
                throw new SecurityException("Thread.CurrentPrincipal cannot be null.");
            }
            if (!Thread.CurrentPrincipal.IsInRole("admin"))
            {
                throw new SecurityException("User must be a member of Admins to access this feature.");
            }
            Console.WriteLine("All material is on your page");
        }
        public static void OnlyForFinancemanager()
        {
            if (Thread.CurrentPrincipal == null)
            {
                throw new SecurityException("Thread.CurrentPrincipal cannot be null.");
            }
            if (!Thread.CurrentPrincipal.IsInRole("finance"))
            {
                throw new SecurityException("User must be a member of Finance managers to access this feature.");
            }
            Console.WriteLine("All material is on your page");
        }
        public static void OnlyForITTechnician()
        {
            if (Thread.CurrentPrincipal == null)
            {
                throw new SecurityException("Thread.CurrentPrincipal cannot be null.");
            }
            if (!Thread.CurrentPrincipal.IsInRole("it"))
            {
                throw new SecurityException("User must be a member of IT Technicians to access this feature.");
            }
            Console.WriteLine("All material is on your page");
        }
        public static void OnlyForSafetyManager()
        {
            if (Thread.CurrentPrincipal == null)
            {
                throw new SecurityException("Thread.CurrentPrincipal cannot be null.");
            }
            if (!Thread.CurrentPrincipal.IsInRole("safety"))
            {
                throw new SecurityException("User must be a member of Safety Managers to access this feature.");
            }
            Console.WriteLine("All material is on your page");
        }

        public static void Check(int opt)
        {
            if (opt == 1)
            {
                try
                {
                    OnlyForAdmins();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"{ex.GetType()}: {ex.Message}");
                }
            }
            if (opt == 2)
            {
                try
                {
                    OnlyForFinancemanager();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"{ex.GetType()}: {ex.Message}");
                }
            }
            if (opt == 3)
            {
                try
                {
                    OnlyForITTechnician();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"{ex.GetType()}: {ex.Message}");
                }
            }
            if (opt == 4)
            {
                try
                {
                    OnlyForSafetyManager();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"{ex.GetType()}: {ex.Message}");
                }
            }
        }
    }
}