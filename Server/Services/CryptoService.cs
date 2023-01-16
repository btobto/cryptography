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

			await foreach (var request in requestStream.ReadAllAsync())
			{
				byte[] chunk = request.Chunk.Bytes.ToByteArray();
				byte[] encryptedChunk = a52.Encrypt(chunk);

				await responseStream.WriteAsync(new Chunk()
				{
					Bytes = ByteString.CopyFrom(encryptedChunk)
				});
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

		public override async Task DecryptRailFence(IAsyncStreamReader<RailFenceRequest> requestStream, IServerStreamWriter<RailFenceResponse> responseStream, ServerCallContext context)
		{
			await foreach (var request in requestStream.ReadAllAsync())
			{
				string decryptedText = RailFence.Decrypt(request.Text, request.Rails);

				await responseStream.WriteAsync(new RailFenceResponse()
				{
					Text = decryptedText
				});
			}
		}

		public override async Task EncryptRailFence(IAsyncStreamReader<RailFenceRequest> requestStream, IServerStreamWriter<RailFenceResponse> responseStream, ServerCallContext context)
		{
			await foreach (var request in requestStream.ReadAllAsync())
			{
				string encryptedText = RailFence.Encrypt(request.Text, request.Rails);

				await responseStream.WriteAsync(new RailFenceResponse()
				{
					Text = encryptedText
				});
			}
		}

		public override async Task EncryptXTEA(IAsyncStreamReader<XTEARequest> requestStream, IServerStreamWriter<Chunk> responseStream, ServerCallContext context)
		{
			await requestStream.MoveNext();

			var key = Encoding.ASCII.GetBytes(requestStream.Current.Key);
			XTEA xtea = new XTEA(key);

			await requestStream.MoveNext();
			var lastChunk = requestStream.Current.Chunk; // buffer last message for padding

			byte[] encryptedChunk;
			await foreach (var request in requestStream.ReadAllAsync())
			{
				var currChunk = lastChunk;

				encryptedChunk = xtea.Encrypt(currChunk.Bytes.ToByteArray());

				await responseStream.WriteAsync(new Chunk()
				{ 
					Bytes = ByteString.CopyFrom(encryptedChunk)
				});

				lastChunk = request.Chunk;
			}

			// if last chunk is full create new chunk with just the padding
			if (lastChunk.Bytes.Length == ChunkSize)
			{
				encryptedChunk = xtea.Encrypt(lastChunk.Bytes.ToByteArray());
				await responseStream.WriteAsync(new Chunk()
				{
					Bytes = ByteString.CopyFrom(encryptedChunk)
				});

				encryptedChunk = xtea.Encrypt(new byte[0], true); // 64 bits of padding
			} 
			else
			{
				encryptedChunk = xtea.Encrypt(lastChunk.Bytes.ToByteArray(), true);
			}

			await responseStream.WriteAsync(new Chunk()
			{
				Bytes = ByteString.CopyFrom(encryptedChunk)
			});
		}

		public override async Task DecryptXTEA(IAsyncStreamReader<XTEARequest> requestStream, IServerStreamWriter<Chunk> responseStream, ServerCallContext context)
		{
			await requestStream.MoveNext();

			var key = Encoding.ASCII.GetBytes(requestStream.Current.Key);
			XTEA xtea = new XTEA(key);

			await requestStream.MoveNext();
			var lastChunk = requestStream.Current.Chunk; // buffer last message to remove padding

			byte[] decryptedChunk;
			await foreach (var request in requestStream.ReadAllAsync())
			{
				var currChunk = lastChunk;

				decryptedChunk = xtea.Decrypt(currChunk.Bytes.ToByteArray());

				await responseStream.WriteAsync(new Chunk()
				{
					Bytes = ByteString.CopyFrom(decryptedChunk)
				});

				lastChunk = request.Chunk;
			}

			decryptedChunk = xtea.Decrypt(lastChunk.Bytes.ToByteArray(), true);
			await responseStream.WriteAsync(new Chunk()
			{
				Bytes = ByteString.CopyFrom(decryptedChunk)
			});
		}
	}
}
