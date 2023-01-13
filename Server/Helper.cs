using System.Collections;

namespace Server
{
	public static class Helper
	{
		public static BitArray StringToBitArray(string str)
		{
			return new BitArray(str.Select(b => b == '1').Reverse().ToArray());
		}
	}
}
