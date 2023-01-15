using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Client
{
	internal static class Helper
	{
		public static async IAsyncEnumerable<(byte[], int)> ReadFileByChunks(string filePath, uint chunkSize)
		{
			using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
			{
				var chunk = new byte[chunkSize];
				int bytesRead;
				while ((bytesRead = await stream.ReadAsync(chunk, 0, chunk.Length)) > 0)
				{
					yield return (chunk, bytesRead);
				}
			}
		}

		public static async IAsyncEnumerable<string> ReadFileByLines(string filePath)
		{
			using (StreamReader reader = new StreamReader(filePath))
			{
				string line;
				while ((line = await reader.ReadLineAsync()) != null)
				{
					yield return line;
				}
			}
		}
	}
}
