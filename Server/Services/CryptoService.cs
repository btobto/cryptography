using Ciphers;
using Google.Protobuf;
using Grpc.Core;
using Server;
using System.Collections;
using System.Drawing;
using System.Text;

namespace Crypto.Server.Services
{
	public class CryptoService : Crypto.CryptoBase
	{
		public const int ChunkSize = 1024 * 64;

		public async override Task DecryptA52(IAsyncStreamReader<A52Request> requestStream, IServerStreamWriter<Chunk> responseStream, ServerCallContext context)
		{
			await requestStream.MoveNext();

			string key = requestStream.Current.Key;
			string iv = requestStream.Current.Iv;

			Console.WriteLine(key);
			Console.WriteLine(iv);

			BitArray keyBits = Helper.StringToBitArray(key);
			BitArray ivBits = Helper.StringToBitArray(iv);

			A52 a52 = new A52(keyBits, ivBits);

			while (await requestStream.MoveNext())
			{
				var request = requestStream.Current;

				byte[] chunk = request.Chunk.Bytes.ToByteArray();
				byte[] encryptedChunk = a52.Encrypt(chunk);

				Chunk response = new Chunk()
				{
					Bytes = ByteString.CopyFrom(encryptedChunk, 0, request.Chunk.Size)
				};

				Console.WriteLine("Sending...");
				await responseStream.WriteAsync(response);
			}
			Console.WriteLine("Done");
		}

		public override async Task EncryptA52(IAsyncStreamReader<A52Request> requestStream, IServerStreamWriter<Chunk> responseStream, ServerCallContext context)
		{
			await requestStream.MoveNext();

			string key = requestStream.Current.Key;
			string iv = requestStream.Current.Iv;

			Console.WriteLine(key);
			Console.WriteLine(iv);

			BitArray keyBits = Helper.StringToBitArray(key);
			BitArray ivBits = Helper.StringToBitArray(iv);

			A52 a52 = new A52(keyBits, ivBits);

			while (await requestStream.MoveNext())
			{
				var request = requestStream.Current;

				byte[] chunk = request.Chunk.Bytes.ToByteArray();
				byte[] encryptedChunk = a52.Encrypt(chunk);

				Chunk response = new Chunk()
				{
					Bytes = ByteString.CopyFrom(encryptedChunk, 0, request.Chunk.Size)
				};

				Console.WriteLine("Sending...");
				await responseStream.WriteAsync(response);
			}
			Console.WriteLine("Done");
		}
	}
}
