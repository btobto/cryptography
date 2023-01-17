using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ciphers
{
	public interface IBlockCipher
	{
		public int BlockSize { get; } // in bytes

		public byte[] Encrypt(byte[] chunk, bool padding = false);

		public byte[] Decrypt(byte[] chunk, bool padding = false);

		public byte[] EncryptBlock(byte[] data);

		public byte[] DecryptBlock(byte[] data);
	}
}
