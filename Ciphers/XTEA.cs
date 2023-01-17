using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ciphers
{
	public class XTEA : IBlockCipher
	{
		private uint[] _key;
		private const uint _delta = 0x9E3779B9;
		private int _numRounds;

		public int BlockSize { 
			get => 8; 
		}

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

			_key = ByteArrayToUInt32Array(key);
			_numRounds = numRounds;
		}

		public byte[] Encrypt(byte[] chunk, bool padding = false)
		{
			int numBlocks = chunk.Length / BlockSize;
			int lastBlockLength = chunk.Length - numBlocks * BlockSize;

			var encryptedChunk = new List<byte>((padding ? numBlocks + 1 : numBlocks) * BlockSize);

			for (int i = 0; i < numBlocks * BlockSize; i += BlockSize)
			{
				byte[] encryptedBlock = EncryptBlock(chunk[i..(i + BlockSize)]);
				encryptedChunk.AddRange(encryptedBlock);
			}

			if (padding)
			{
				var paddedBlock = AddPKCS7Padding(chunk[^lastBlockLength..], BlockSize);
				var encryptedBlock = EncryptBlock(paddedBlock);
				encryptedChunk.AddRange(encryptedBlock);
			}

			return encryptedChunk.ToArray();
		}

		public byte[] Decrypt(byte[] chunk, bool padding = false)
		{
			int numBlocks = chunk.Length / BlockSize;

			List<byte> decryptedChunk = new List<byte>(chunk.Length);

			for (int i = 0; i < (padding ? numBlocks - 1 : numBlocks) * BlockSize; i += BlockSize)
			{
				byte[] decryptedBlock = DecryptBlock(chunk[i..(i + BlockSize)]);
				decryptedChunk.AddRange(decryptedBlock);
			}

			if (padding)
			{
				byte[] lastBlock = DecryptBlock(chunk[^8..]);
				var unpaddedBlock = RemovePKCS7Padding(lastBlock);
				decryptedChunk.AddRange(unpaddedBlock);
			}

			return decryptedChunk.ToArray();
		}

		public byte[] EncryptBlock(byte[] data)
		{
			var v = ByteArrayToUInt32Array(data);
			var v0 = v[0];
			var v1 = v[1];

			uint sum = 0;

			for (int i = 0; i < _numRounds; i++)
			{
				v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + _key[sum & 3]);
				sum += _delta;
				v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + _key[(sum >> 11) & 3]);
			}

			return UInt32ArrayToByteArray(v0, v1);
		}

		public byte[] DecryptBlock(byte[] data)
		{
			var v = ByteArrayToUInt32Array(data);
			var v0 = v[0];
			var v1 = v[1];

			uint sum = _delta * (uint)_numRounds;

			for (int i = 0; i < _numRounds; i++)
			{
				v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + _key[(sum >> 11) & 3]);
				sum -= _delta;
				v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + _key[sum & 3]);
			}

			return UInt32ArrayToByteArray(v0, v1); ;
		}

		public static byte[] AddPKCS7Padding(byte[] lastBlock, int blockSize)
		{
			if (blockSize < lastBlock.Length)
			{
				throw new ArgumentException("Cipher block size must be less than size of current block.");
			}	

			int paddingLength = blockSize - lastBlock.Length;

			var paddedBlock = lastBlock
				.Take(lastBlock.Length)
				.Concat(Enumerable.Range(0, paddingLength).Select(_ => (byte)paddingLength))
				.ToArray();
			
			return paddedBlock;
		}

		public static byte[] RemovePKCS7Padding(byte[] block)
		{
			int paddingLength = block[^1];

			return block.Take(block.Length - paddingLength).ToArray();
		}

		public static byte[] UInt32ArrayToByteArray(params uint[] uints)
		{
			byte[] bytes = new byte[uints.Length * sizeof(uint)];
			Buffer.BlockCopy(uints, 0, bytes, 0, bytes.Length);
			return bytes;
		}

		public static uint[] ByteArrayToUInt32Array(byte[] bytes)
		{
			uint[] uints = new uint[bytes.Length / sizeof(uint)];
			Buffer.BlockCopy(bytes, 0, uints, 0, uints.Length * sizeof(uint));
			return uints;
		}
	}
}