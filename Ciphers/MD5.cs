using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ciphers
{
	public class MD5
	{
		private long fileSize = 0;

		private uint[] buffer = new uint[]
		{
			0x67452301,
			0xefcdab89,
			0x98badcfe,
			0x10325476
		};

		private readonly static uint[] K = new uint[64] 
		{
			0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
			0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
			0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
			0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
			0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
			0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
			0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
			0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
			0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
			0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
			0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
			0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
			0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
			0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
			0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
			0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
		};

		private readonly static int[] S = new int[64] 
		{
			7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
			5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
			4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
			6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
		};

		public static uint RotateLeft(uint x, int n)
		{
			return (x << n) | (x >> (32 - n));
		}

		public void ProcessChunk(byte[] chunk, bool padding = false)
		{
			fileSize += chunk.Length;

			if (padding)
			{
				var paddedChunk = new List<byte>(chunk) { 0x80 };
				while (paddedChunk.Count % 64 != 56) paddedChunk.Add(0x00);

				byte[] lengthBytes = BitConverter.GetBytes(fileSize * 8);
				paddedChunk.AddRange(lengthBytes);

				chunk = paddedChunk.ToArray();
			}

			for (int i = 0; i < chunk.Length; i += 64)
			{
				uint[] M = new uint[16];

				for (int j = 0; j < 16; j++)
				{
					M[j] = BitConverter.ToUInt32(chunk, i + (j * 4));
				}

				ProcessBlock(M);
			}
		}

		public void ProcessBlock(uint[] M)
		{
			uint A = buffer[0];
			uint B = buffer[1];
			uint C = buffer[2];
			uint D = buffer[3];

			uint E, j;

			for (uint i = 0; i < 64; i++)
			{
				switch (i / 16)
				{
					case 0:
						E = (B & C) | (~B & D);
						j = i;
						break;
					case 1:
						E = (D & B) | (~D & C);
						j = ((i * 5) + 1) % 16;
						break;
					case 2:
						E = B ^ C ^ D;
						j = ((i * 3) + 5) % 16;
						break;
					default:
						E = C ^ (B | ~D);
						j = (i * 7) % 16;
						break;
				}

				uint tmp = D;
				D = C;
				C = B;
				B = B + RotateLeft(A + E + K[i] + M[j], S[i]);
				A = tmp;
			}

			buffer[0] += A;
			buffer[1] += B;
			buffer[2] += C;
			buffer[3] += D;
		}

		public string GetHash()
		{
			StringBuilder output = new StringBuilder();

			foreach (var w in buffer)
			{
				output.Append(string.Join("", BitConverter.GetBytes(w).Select(b => b.ToString("x2"))));
			}

			return output.ToString();
		}
	}
}
