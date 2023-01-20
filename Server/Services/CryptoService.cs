using Ciphers;
using Google.Protobuf;
using Grpc.Core;
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

			BitArray keyBits = new BitArray(key.Select(b => b == '1').Reverse().ToArray());
			BitArray ivBits = new BitArray(iv.Select(b => b == '1').Reverse().ToArray());
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

				encryptedChunk = xtea.EncryptChunk(currChunk.Bytes.ToByteArray());

				await responseStream.WriteAsync(new Chunk()
				{ 
					Bytes = ByteString.CopyFrom(encryptedChunk)
				});

				lastChunk = request.Chunk;
			}

			// if last chunk is full create new chunk with just the padding
			if (lastChunk.Bytes.Length == ChunkSize)
			{
				encryptedChunk = xtea.EncryptChunk(lastChunk.Bytes.ToByteArray());
				await responseStream.WriteAsync(new Chunk()
				{
					Bytes = ByteString.CopyFrom(encryptedChunk)
				});

				encryptedChunk = xtea.EncryptChunk(new byte[0], true); // 64 bits of padding
			} 
			else
			{
				encryptedChunk = xtea.EncryptChunk(lastChunk.Bytes.ToByteArray(), true);
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

				decryptedChunk = xtea.DecryptChunk(currChunk.Bytes.ToByteArray());

				await responseStream.WriteAsync(new Chunk()
				{
					Bytes = ByteString.CopyFrom(decryptedChunk)
				});

				lastChunk = request.Chunk;
			}

			decryptedChunk = xtea.DecryptChunk(lastChunk.Bytes.ToByteArray(), true);
			await responseStream.WriteAsync(new Chunk()
			{
				Bytes = ByteString.CopyFrom(decryptedChunk)
			});
		}

		public override async Task EncryptXTEAPCBC(IAsyncStreamReader<XTEAPCBCRequest> requestStream, IServerStreamWriter<Chunk> responseStream, ServerCallContext context)
		{
			await requestStream.MoveNext();

			var key = Encoding.ASCII.GetBytes(requestStream.Current.Key);
			var iv = Encoding.ASCII.GetBytes(requestStream.Current.Iv);
			PCBC pcbc = new PCBC(new XTEA(key), iv);

			await requestStream.MoveNext();
			var lastChunk = requestStream.Current.Chunk;

			byte[] encryptedChunk;
			await foreach (var request in requestStream.ReadAllAsync())
			{
				var currChunk = lastChunk;

				encryptedChunk = pcbc.Encrypt(currChunk.Bytes.ToByteArray());

				await responseStream.WriteAsync(new Chunk()
				{
					Bytes = ByteString.CopyFrom(encryptedChunk)
				});

				lastChunk = request.Chunk;
			}

			if (lastChunk.Bytes.Length == ChunkSize)
			{
				encryptedChunk = pcbc.Encrypt(lastChunk.Bytes.ToByteArray());
				await responseStream.WriteAsync(new Chunk()
				{
					Bytes = ByteString.CopyFrom(encryptedChunk)
				});

				encryptedChunk = pcbc.Encrypt(new byte[0], true);
			}
			else
			{
				encryptedChunk = pcbc.Encrypt(lastChunk.Bytes.ToByteArray(), true);
			}

			await responseStream.WriteAsync(new Chunk()
			{
				Bytes = ByteString.CopyFrom(encryptedChunk)
			});
		}

		public override async Task DecryptXTEAPCBC(IAsyncStreamReader<XTEAPCBCRequest> requestStream, IServerStreamWriter<Chunk> responseStream, ServerCallContext context)
		{
			await requestStream.MoveNext();

			var key = Encoding.ASCII.GetBytes(requestStream.Current.Key);
			var iv = Encoding.ASCII.GetBytes(requestStream.Current.Iv);
			PCBC pcbc = new PCBC(new XTEA(key), iv);

			await requestStream.MoveNext();
			var lastChunk = requestStream.Current.Chunk;

			byte[] decryptedChunk;
			await foreach (var request in requestStream.ReadAllAsync())
			{
				var currChunk = lastChunk;

				decryptedChunk = pcbc.Decrypt(currChunk.Bytes.ToByteArray());

				await responseStream.WriteAsync(new Chunk()
				{
					Bytes = ByteString.CopyFrom(decryptedChunk)
				});

				lastChunk = request.Chunk;
			}

			decryptedChunk = pcbc.Decrypt(lastChunk.Bytes.ToByteArray(), true);
			await responseStream.WriteAsync(new Chunk()
			{
				Bytes = ByteString.CopyFrom(decryptedChunk)
			});
		}

		public override async Task<MD5Response> ComputeMD5Hash(IAsyncStreamReader<Chunk> requestStream, ServerCallContext context)
		{
			MD5 md5 = new MD5();

			await requestStream.MoveNext();
			Chunk lastChunk = requestStream.Current;

			await foreach (var request in requestStream.ReadAllAsync())
			{
				Chunk currChunk = lastChunk;

				md5.ProcessChunk(currChunk.Bytes.ToByteArray());

				lastChunk = request;
			}

			md5.ProcessChunk(lastChunk.Bytes.ToByteArray(), true);

			return new MD5Response() { Hash = md5.GetHash() };
		}

		public override async Task EncryptXTEAParallel(IAsyncStreamReader<XTEAParallelRequest> requestStream, IServerStreamWriter<Chunk> responseStream, ServerCallContext context)
		{
			await requestStream.MoveNext();

			var key = Encoding.ASCII.GetBytes(requestStream.Current.Key);
			int numThreads = requestStream.Current.NumThreads;
			XTEA xtea = new XTEA(key);

			await requestStream.MoveNext();
			var lastChunk = requestStream.Current.Chunk;

			byte[] encryptedChunk;
			await foreach (var request in requestStream.ReadAllAsync())
			{
				var currChunk = lastChunk;

				encryptedChunk = xtea.EncryptParallel(numThreads, currChunk.Bytes.ToByteArray());

				await responseStream.WriteAsync(new Chunk()
				{
					Bytes = ByteString.CopyFrom(encryptedChunk)
				});

				lastChunk = request.Chunk;
			}

			// if last chunk is full create new chunk with just the padding
			if (lastChunk.Bytes.Length == ChunkSize)
			{
				encryptedChunk = xtea.EncryptParallel(numThreads, lastChunk.Bytes.ToByteArray());
				await responseStream.WriteAsync(new Chunk()
				{
					Bytes = ByteString.CopyFrom(encryptedChunk)
				});

				encryptedChunk = xtea.EncryptParallel(numThreads, new byte[0], true); // 64 bits of padding
			}
			else
			{
				encryptedChunk = xtea.EncryptParallel(numThreads, lastChunk.Bytes.ToByteArray(), true);
			}

			await responseStream.WriteAsync(new Chunk()
			{
				Bytes = ByteString.CopyFrom(encryptedChunk)
			});
		}

		public override async Task DecryptXTEAParallel(IAsyncStreamReader<XTEAParallelRequest> requestStream, IServerStreamWriter<Chunk> responseStream, ServerCallContext context)
		{
			await requestStream.MoveNext();

			var key = Encoding.ASCII.GetBytes(requestStream.Current.Key);
			int numThreads = requestStream.Current.NumThreads;
			XTEA xtea = new XTEA(key);

			await requestStream.MoveNext();
			var lastChunk = requestStream.Current.Chunk; // buffer last message to remove padding

			byte[] decryptedChunk;
			await foreach (var request in requestStream.ReadAllAsync())
			{
				var currChunk = lastChunk;

				decryptedChunk = xtea.DecryptParallel(numThreads, currChunk.Bytes.ToByteArray());

				await responseStream.WriteAsync(new Chunk()
				{
					Bytes = ByteString.CopyFrom(decryptedChunk)
				});

				lastChunk = request.Chunk;
			}

			decryptedChunk = xtea.DecryptParallel(numThreads, lastChunk.Bytes.ToByteArray(), true);
			await responseStream.WriteAsync(new Chunk()
			{
				Bytes = ByteString.CopyFrom(decryptedChunk)
			});
		}
	}
}
