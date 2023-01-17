using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ciphers
{
	internal class PCBC
	{
		private IBlockCipher _cipher;
		private byte[] _iv;
		private int _blockSize; // in bytes
		private byte[] _propagatingBlock;

		public PCBC(IBlockCipher cipher, byte[] iv, int blockSizeBytes)
		{
			if (iv.Length != blockSizeBytes)
			{
				throw new ArgumentException("Initialization vector length must be equal to block size.");
			}

			_cipher = cipher;
			_iv = iv;
			_propagatingBlock = new byte[blockSizeBytes];
			_blockSize = blockSizeBytes;
			Buffer.BlockCopy(_iv, 0, _propagatingBlock, 0, blockSizeBytes);
		}

		public void XORWithBlock(byte[] block)
		{
			for (int i = 0; i < _blockSize; i++)
			{
				_propagatingBlock[i] ^= block[i];
			}
		}

		public byte[] Encrypt(byte[] chunk, bool padding)
		{
			int numBlocks = chunk.Length / _blockSize;
			int lastBlockLength = chunk.Length - numBlocks * _blockSize;

			var encryptedChunk = new List<byte>(padding ? (numBlocks + 1) * _blockSize : numBlocks * _blockSize);

			for (int i = 0; i < numBlocks * _blockSize; i += _blockSize)
			{
				var currBlock = chunk[i..(i + _blockSize)];
				XORWithBlock(currBlock);

				var encryptedBlock = _cipher.EncryptBlock(_propagatingBlock);
				encryptedChunk.AddRange(encryptedBlock);

				_propagatingBlock = encryptedBlock;
				XORWithBlock(currBlock);
			}

			if (padding)
			{
				var paddedBlock = XTEA.AddPKCS7Padding(chunk[^lastBlockLength..], _blockSize);
				XORWithBlock(paddedBlock);

				var encryptedBlock = _cipher.EncryptBlock(_propagatingBlock);
				encryptedChunk.AddRange(encryptedBlock);
			}

			return encryptedChunk.ToArray();
		}

		public byte[] Decrypt(byte[] chunk, bool padding)
		{
			int numBlocks = chunk.Length / 8;

			List<byte> decryptedChunk = new List<byte>(chunk.Length);

			for (int i = 0; i < (padding ? numBlocks - 1 : numBlocks) * 8; i += 8)
			{
				var currBlock = chunk[i..(i + 8)];
				var decryptedBlock = _cipher.DecryptBlock(currBlock);

				XORWithBlock(decryptedBlock);
				decryptedChunk.AddRange(_propagatingBlock);

				XORWithBlock(currBlock);
			}

			if (padding)
			{
				byte[] decryptedBlock = _cipher.DecryptBlock(chunk[^8..]);
				XORWithBlock(decryptedBlock);

				var lastBlock = XTEA.RemovePKCS7Padding(_propagatingBlock);
				decryptedChunk.AddRange(lastBlock);
			}

			return decryptedChunk.ToArray();
		}
	}
}
