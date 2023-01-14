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

		public async Task CryptA52(IAsyncStreamReader<A52Request> requestStream, IServerStreamWriter<Chunk> responseStream, ServerCallContext context)
		{
			await requestStream.MoveNext();

			string key = requestStream.Current.Key;
			string iv = requestStream.Current.Iv;

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

				await responseStream.WriteAsync(response);
			}
		}

		public async override Task DecryptA52(IAsyncStreamReader<A52Request> requestStream, IServerStreamWriter<Chunk> responseStream, ServerCallContext context)
		{
			await CryptA52(requestStream, responseStream, context);
		}

		public override async Task EncryptA52(IAsyncStreamReader<A52Request> requestStream, IServerStreamWriter<Chunk> responseStream, ServerCallContext context)
		{
			await CryptA52(requestStream, responseStream, context);
		}
	}
}
