using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography
{
	public class PCBC
	{
		private IBlockCipher _cipher;
		private byte[] _iv;
		private int _blockSize; // in bytes
		private byte[] _workingBlock;

		public PCBC(IBlockCipher cipher, byte[] iv)
		{
			if (iv.Length != cipher.BlockSize)
			{
				throw new ArgumentException("Initialization vector length must be equal to block size.");
			}

			_cipher = cipher;
			_iv = iv;
			_workingBlock = new byte[cipher.BlockSize];
			_blockSize = cipher.BlockSize;
			Buffer.BlockCopy(_iv, 0, _workingBlock, 0, cipher.BlockSize);
		}

		public void XORWithBlock(byte[] block)
		{
			for (int i = 0; i < _blockSize; i++)
			{
				_workingBlock[i] ^= block[i];
			}
		}

		public byte[] EncryptChunk(byte[] chunk, bool lastChunk = false)
		{
			if (!lastChunk && chunk.Length % _blockSize != 0)
			{
				throw new ArgumentException($"Chunk size must be a multiple of {_blockSize}B if chunk is not last.");
			}

			int numBlocks = chunk.Length / _blockSize;
			int lastBlockLength = chunk.Length - numBlocks * _blockSize;

			var encryptedChunk = new List<byte>((lastChunk ? numBlocks + 1 : numBlocks) * _blockSize);

			for (int i = 0; i < numBlocks * _blockSize; i += _blockSize)
			{
				var currBlock = chunk[i..(i + _blockSize)];
				XORWithBlock(currBlock);

				var encryptedBlock = _cipher.EncryptBlock(_workingBlock);
				encryptedChunk.AddRange(encryptedBlock);

				_workingBlock = encryptedBlock;
				XORWithBlock(currBlock);
			}

			if (lastChunk)
			{
				var paddedBlock = XTEA.AddPKCS7Padding(chunk[^lastBlockLength..], _blockSize);
				XORWithBlock(paddedBlock);

				var encryptedBlock = _cipher.EncryptBlock(_workingBlock);
				encryptedChunk.AddRange(encryptedBlock);
			}

			return encryptedChunk.ToArray();
		}

		public byte[] DecryptChunk(byte[] chunk, bool lastChunk = false)
		{
			if (!lastChunk && chunk.Length % _blockSize != 0)
			{
				throw new ArgumentException($"Chunk size must be a multiple of {_blockSize}B if chunk is not last.");
			}

			int numBlocks = chunk.Length / 8;

			List<byte> decryptedChunk = new List<byte>(chunk.Length);

			for (int i = 0; i < (lastChunk ? numBlocks - 1 : numBlocks) * 8; i += 8)
			{
				var currBlock = chunk[i..(i + 8)];
				var decryptedBlock = _cipher.DecryptBlock(currBlock);

				XORWithBlock(decryptedBlock);
				decryptedChunk.AddRange(_workingBlock);

				XORWithBlock(currBlock);
			}

			if (lastChunk)
			{
				var decryptedBlock = _cipher.DecryptBlock(chunk[^8..]);
				XORWithBlock(decryptedBlock);

				var lastBlock = XTEA.RemovePKCS7Padding(_workingBlock);
				decryptedChunk.AddRange(lastBlock);
			}

			return decryptedChunk.ToArray();
		}
	}
}
