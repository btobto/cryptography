using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography
{
	internal class Register
	{
		private BitArray _bits;
		private int[] _feedback;
		private int[] _tap;

		public Register(int size, int[] feedback, int[] tap)
		{
			_bits = new BitArray(size);
			_feedback = feedback;
			_tap = tap;
		}

		public BitArray Bits { get => _bits; set => _bits = value; }

		public bool this[int index]
		{
			get => _bits[index];
			set => _bits[index] = value;
		}

		public void Clock(bool clk)
		{
			if (clk)
			{
				bool lsb = _feedback.Select(i => _bits[i]).Aggregate((acc, x) => acc ^ x);
				_bits.LeftShift(1);
				_bits[0] = lsb;
			}
		}

		public bool CalculateOutput(int negateBit)
		{
			bool majority = A52.Majority(
				_tap.Select(i => i == negateBit ? !_bits[i] : _bits[i]).ToArray()
			);
			return _bits[_bits.Length - 1] ^ majority;
		}
	}
}
