using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ciphers
{
	public static class RailFence
	{
		public static string Encrypt(string text, int rails)
		{
			if (rails <= 0)
			{
				throw new ArgumentException("Rails number must be greater than 0.");
			}

			StringBuilder output = new StringBuilder();

			int currRail = 0;
			for (; currRail < rails - 1; currRail++)
			{
				int skip = 2 * (rails - currRail - 1);
				int j = 0;
				for (int i = currRail; i < text.Length;)
				{
					output.Append(text[i]);

					if (currRail == 0 || j % 2 == 0)
					{
						i += skip;
					}
					else
					{
						i += 2 * (rails - 1) - skip;
					}
					j++;
				}
			}

			for (int i = currRail; i < text.Length; i += 2 * (rails - 1))
			{
				output.Append(text[i]);
			}

			return output.ToString();
		}

		public static string Decrypt(string text, int rails)
		{
			if (rails <= 0)
			{
				throw new ArgumentException("Rails number must be greater than 0.");
			}

			char[] output = new char[text.Length];

			int currRail = 0;
			int k = 0;
			for (; currRail < rails - 1; currRail++)
			{
				int skip = 2 * (rails - currRail - 1);
				int j = 0;
				for (int i = currRail; i < text.Length;)
				{
					output[i] = text[k++];

					if (currRail == 0 || j % 2 == 0)
					{
						i += skip;
					}
					else
					{
						i += 2 * (rails - 1) - skip;
					}
					j++;
				}
			}

			for (int i = currRail; i < text.Length; i += 2 * (rails - 1))
			{
				output[i] = text[k++];
			}

			return new string(output);
		}
	}
}
