using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography
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

		public byte[] EncryptChunk(byte[] chunk, bool lastChunk = false)
		{
			if (!lastChunk && chunk.Length % BlockSize != 0)
			{
				throw new ArgumentException($"Chunk size must be a multiple of {BlockSize}B if chunk is not last.");
			}

			int numBlocks = chunk.Length / BlockSize;
			int lastBlockLength = chunk.Length - numBlocks * BlockSize;

			var encryptedChunk = new List<byte>((lastChunk ? numBlocks + 1 : numBlocks) * BlockSize);

			for (int i = 0; i < numBlocks * BlockSize; i += BlockSize)
			{
				byte[] encryptedBlock = EncryptBlock(chunk[i..(i + BlockSize)]);
				encryptedChunk.AddRange(encryptedBlock);
			}

			if (lastChunk)
			{
				var paddedBlock = AddPKCS7Padding(chunk[^lastBlockLength..], BlockSize);
				var encryptedBlock = EncryptBlock(paddedBlock);
				encryptedChunk.AddRange(encryptedBlock);
			}

			return encryptedChunk.ToArray();
		}

		public byte[] DecryptChunk(byte[] chunk, bool lastChunk = false)
		{
			if (!lastChunk && chunk.Length % BlockSize != 0)
			{
				throw new ArgumentException($"Chunk size must be a multiple of {BlockSize}B if chunk is not last.");
			}

			int numBlocks = chunk.Length / BlockSize;

			List<byte> decryptedChunk = new List<byte>(chunk.Length);

			for (int i = 0; i < (lastChunk ? numBlocks - 1 : numBlocks) * BlockSize; i += BlockSize)
			{
				byte[] decryptedBlock = DecryptBlock(chunk[i..(i + BlockSize)]);
				decryptedChunk.AddRange(decryptedBlock);
			}

			if (lastChunk)
			{
				byte[] lastBlock = DecryptBlock(chunk[^BlockSize..]);
				var unpaddedBlock = RemovePKCS7Padding(lastBlock);
				decryptedChunk.AddRange(unpaddedBlock);
			}

			return decryptedChunk.ToArray();
		}

		public byte[] EncryptParallel(int numThreads, byte[] chunk, bool lastChunk = false)
		{
			if (!lastChunk && chunk.Length % BlockSize != 0)
			{
				throw new ArgumentException($"Chunk size must be a multiple of {BlockSize}B if chunk is not last.");
			}

			int numBlocks = chunk.Length / BlockSize;
			int lastBlockLength = chunk.Length - numBlocks * BlockSize;

			var encryptedBlocks = Enumerable.Repeat(new byte[0], numBlocks).ToList();

			Parallel.For(0, numBlocks, new ParallelOptions { MaxDegreeOfParallelism = numThreads }, i =>
			{
				int blockStart = i * BlockSize;
				byte[] encryptedBlock = EncryptBlock(chunk[blockStart..(blockStart + BlockSize)]);
				encryptedBlocks[i] = encryptedBlock;
			});

			var encyptedChunk = encryptedBlocks.SelectMany(b => b);

			if (lastChunk)
			{
				var paddedBlock = AddPKCS7Padding(chunk[^lastBlockLength..], BlockSize);
				var encryptedBlock = EncryptBlock(paddedBlock);
				encyptedChunk.Concat(encryptedBlock);
			}

			return encyptedChunk.ToArray();
		}

		public byte[] DecryptParallel(int numThreads, byte[] chunk, bool lastChunk = false)
		{
			if (!lastChunk && chunk.Length % BlockSize != 0)
			{
				throw new ArgumentException($"Chunk size must be a multiple of {BlockSize}B if chunk is not last.");
			}

			int numBlocks = chunk.Length / BlockSize;

			var decryptedBlocks = Enumerable.Repeat(new byte[0], numBlocks).ToList();

			Parallel.For(0, numBlocks, new ParallelOptions { MaxDegreeOfParallelism = numThreads }, i =>
			{
				int blockStart = i * BlockSize;
				byte[] decryptedBlock = DecryptBlock(chunk[blockStart..(blockStart + BlockSize)]);
				decryptedBlocks[i] = decryptedBlock;
			});

			var decryptedChunk = decryptedBlocks.SelectMany(b => b);

			if (lastChunk)
			{
				byte[] lastBlock = DecryptBlock(chunk[^BlockSize..]);
				var unpaddedBlock = RemovePKCS7Padding(lastBlock);
				decryptedChunk.Concat(unpaddedBlock);
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
				.Concat(Enumerable.Repeat((byte)paddingLength, paddingLength))
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