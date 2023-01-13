using System.Collections;

namespace Ciphers
{
	public class A52
	{
		private const int KeystreamLength = 228;
		private const int DiscardLength = 99;

		private BitArray _key, _iv;
		private Register _R1, _R2, _R3, _R4;

		public A52(BitArray key, BitArray iv)
		{
			if (key.Length != 64)
			{
				throw new ArgumentException("Key length must be 64.");
			}

			if (iv.Length != 22)
			{
				throw new ArgumentException("Count length must be 22.");
			}

			_R1 = new Register(19, new int[] { 13, 16, 17, 18 }, new int[] { 12, 14, 15 });
			_R2 = new Register(22, new int[] { 20, 21 }, new int[] { 9, 13, 16 });
			_R3 = new Register(23, new int[] { 7, 20, 21, 22 }, new int[] { 13, 16, 18 });
			_R4 = new Register(17, new int[] { 11, 16 }, new int[] { 3, 7, 10 });

			_key = (BitArray)key.Clone();
			_iv = (BitArray)iv.Clone();

			KeySetup();
		}

		public void KeySetup()
		{
			_R1.Bits.SetAll(false);
			_R2.Bits.SetAll(false);
			_R3.Bits.SetAll(false);
			_R4.Bits.SetAll(false);

			foreach (bool bit in _key)
			{
				ClockRegisters(true);
				_R1[0] ^= bit;
				_R2[0] ^= bit;
				_R3[0] ^= bit;
				_R4[0] ^= bit;
			}

			foreach (bool bit in _iv)
			{
				ClockRegisters(true);
				_R1[0] ^= bit;
				_R2[0] ^= bit;
				_R3[0] ^= bit;
				_R4[0] ^= bit;
			}

			_R1[15] = _R2[16] = _R3[18] = _R4[10] = true;

			for (int i = 0; i < DiscardLength; i++)
			{
				GenerateOutputBit();
			}
		}

		public void ClockRegisters(bool all = false)
		{
			bool majority = Majority(_R4[3], _R4[7], _R4[10]);
			_R1.Clock(all || _R4[10] == majority);
			_R2.Clock(all || _R4[3] == majority);
			_R3.Clock(all || _R4[7] == majority);
			_R4.Clock(true);
		}

		public static bool Majority(params bool[] bits)
		{
			return bits.Count(t => t) > bits.Length / 2;
		}

		public bool GenerateOutputBit()
		{
			ClockRegisters();

			return _R1.CalculateOutput(14) ^ _R2.CalculateOutput(16) ^ _R3.CalculateOutput(13);
		}

		public BitArray GenerateKeystream()
		{
			BitArray output = new BitArray(KeystreamLength);

			for (int i = 0; i < KeystreamLength; i++)
			{
				output[i] = GenerateOutputBit();
			}

			return output;
		}

		public byte[] Crypt(byte[] data)
		{
			int dataLengthBits = data.Length * 8;
			int numKeystreams = (int)Math.Ceiling((double)dataLengthBits / KeystreamLength);
			var keystreams = Enumerable.Range(0, numKeystreams).Select(_ => GenerateKeystream()).ToArray();

			BitArray outputBits = new BitArray(data);

			for (int i = 0; i < dataLengthBits; i++)
			{
				BitArray ks = keystreams[i / KeystreamLength];
				outputBits[i] ^= ks[i % KeystreamLength];
			}

			byte[] outputBytes = new byte[data.Length];
			outputBits.CopyTo(outputBytes, 0);

			return outputBytes;
		}

		public byte[] Crypt2(byte[] data)
		{
			BitArray outputBits = new BitArray(data);
			for (int i = 0; i < data.Length * 8; i++)
			{
				outputBits[i] ^= GenerateOutputBit();
			}

			byte[] outputBytes = new byte[data.Length];
			outputBits.CopyTo(outputBytes, 0);

			return outputBytes;
		}

		public byte[] Encrypt(byte[] data)
		{
			return Crypt(data);
		}

		public byte[] Decrypt(byte[] data)
		{
			return Crypt(data);
		}
	}
}