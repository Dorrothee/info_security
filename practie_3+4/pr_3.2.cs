using System.Security.Cryptography;
using System.Text;

class MD5Program
{
	//guid-{564c8da6-0440-88ec-d453-0bbad57c6036}
	public static void Main()
	{
		int n = 9;
		int m = 8;
		int h = n > m ? n : m;
		int[] a = new int[h];
		for (int i = 0; i < h; i++)
			a[i] = 0;
		Print(a, m);
		while (NextSet(a, h, m))
			Print(a, m);
	}

	public static bool NextSet(int[] a, int n, int m)
	{
		int j = m - 1;
		while (j >= 0 && a[j] == n) j--;
		if (j < 0) return false;
		if (a[j] >= n)
			j--;
		a[j]++;
		if (j == m - 1) return true;
		for (int k = j + 1; k < m; k++)
			a[k] = 0;
		return true;
	}
	public static void Print(int[] a, int n)
	{
		string given_hash = "po1MVkAE7IjUUwu61XxgNg==";
		string str = "";
		for (int i = 0; i < n; i++)
			str = str + a[i];
		var md5forstr = ComputeHashMD5(Encoding.Unicode.GetBytes(str));
		var md5found = Convert.ToBase64String(md5forstr);
		if (given_hash.Equals(md5found))
		{
			Console.WriteLine("FOUND PASSWORD IS: ");
			Console.WriteLine(str);
		}
	}
	static byte[] ComputeHashMD5(byte[] dataforMD5)
	{
		using (var md5 = MD5.Create())
		{
			return md5.ComputeHash(dataforMD5);
		}
	}
}





//password is 20192020