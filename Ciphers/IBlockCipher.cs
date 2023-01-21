using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography
{
	public interface IBlockCipher
	{
		public int BlockSize { get; } // in bytes

		public byte[] EncryptChunk(byte[] chunk, bool padding = false);

		public byte[] DecryptChunk(byte[] chunk, bool padding = false);

		public byte[] EncryptBlock(byte[] data);

		public byte[] DecryptBlock(byte[] data);
	}
}
