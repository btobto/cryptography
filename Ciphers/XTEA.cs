using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ciphers
{
	public class XTEA
	{
		private uint[] _key;
		private const uint _delta = 0x9E3779B9;
		private int _numRounds;

		public XTEA(byte[] key, int numRounds = 64)
		{
			if (key.Length != 16)
			{
				throw new ArgumentException("Key must be 128 bits.");
			}

			if (numRounds < 32)
			{
				throw new ArgumentException("Number of cycles must not be less that 32.");
			}

			_key = new uint[4];
			for (int i = 0; i < 4; i++)
			{
				_key[i] = BitConverter.ToUInt32(key, i * 4);
			}

			_numRounds = numRounds;
		}

		public byte[] Encrypt(byte[] chunk, bool padding = false)
		{
			int numBlocks = chunk.Length / 8;
			int lastBlockLength = chunk.Length - numBlocks * 8;

			var encryptedChunk = new List<byte>(padding ? (numBlocks + 1) * 8 : numBlocks * 8);

			for (int i = 0; i < numBlocks * 8; i += 8)
			{
				byte[] encryptedBlock = EncryptBlock(chunk[i..(i + 8)]);
				encryptedChunk.AddRange(encryptedBlock);
			}

			// PKCS 7 padding
			if (padding)
			{
				int paddingLength = 8 - lastBlockLength;
				var lastBlock = new List<byte>(chunk[(numBlocks * 8)..]);

				lastBlock.AddRange(Enumerable.Range(0, paddingLength).Select(_ => (byte)paddingLength));

				byte[] encryptedBlock = EncryptBlock(lastBlock.ToArray());
				encryptedChunk.AddRange(encryptedBlock);
			}

			return encryptedChunk.ToArray();
		}

		public byte[] Decrypt(byte[] chunk, bool padding = false)
		{
			int numBlocks = chunk.Length / 8;

			List<byte> decryptedChunk = new List<byte>(chunk.Length);

			for (int i = 0; i < (padding ? numBlocks - 1 : numBlocks) * 8; i += 8)
			{
				byte[] decryptedBlock = DecryptBlock(chunk[i..(i + 8)]);
				decryptedChunk.AddRange(decryptedBlock);
			}

			if (padding)
			{
				byte[] lastBlock = DecryptBlock(chunk[(numBlocks * 8 - 8)..]);
				int numPads = lastBlock[lastBlock.Length - 1];
				decryptedChunk.AddRange(lastBlock.Take(8 - numPads));
			}

			return decryptedChunk.ToArray();
		}

		public static (uint, uint) ByteArrayToUInts(byte[] data)
		{
			if (data.Length != 8)
			{
				throw new ArgumentException("Block must be 64 bits long.");
			}

			return (BitConverter.ToUInt32(data, 0), BitConverter.ToUInt32(data, 4));
		}

		public static byte[] UIntsToByteArray(uint v0, uint v1)
		{
			byte[] output = new byte[8];

			Array.Copy(BitConverter.GetBytes(v0), 0, output, 0, 4);
			Array.Copy(BitConverter.GetBytes(v1), 0, output, 4, 4);

			return output;
		}

		public byte[] EncryptBlock(byte[] data)
		{
			var (v0, v1) = ByteArrayToUInts(data);

			uint sum = 0;

			for (int i = 0; i < _numRounds; i++)
			{
				v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + _key[sum & 3]);
				sum += _delta;
				v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + _key[(sum >> 11) & 3]);
			}

			return UIntsToByteArray(v0, v1);
		}

		public byte[] DecryptBlock(byte[] data)
		{
			var (v0, v1) = ByteArrayToUInts(data);

			uint sum = 0xC6EF3720;

			for (int i = 0; i < _numRounds; i++)
			{
				v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + _key[(sum >> 1) & 3]);
				sum -= _delta;
				v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + _key[sum & 3]);
			}

			return UIntsToByteArray(v0, v1);
		}
	}
}
