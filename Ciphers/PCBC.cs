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
		public int _blockSizeBytes;

		public PCBC(IBlockCipher cipher, byte[] iv, int blockSizeBytes)
		{
			if (iv.Length != blockSizeBytes)
			{
				throw new ArgumentException("Initialization vector length must be equal to block size.");
			}

			_cipher = cipher;
			_iv = iv;
			_blockSizeBytes = blockSizeBytes;
		}

		public byte[] Encrypt(byte[] chunk, bool padding)
		{
			throw new NotImplementedException();
		}

		public byte[] Decrypt(byte[] chunk, bool padding)
		{
			throw new NotImplementedException();
		}
	}
}
