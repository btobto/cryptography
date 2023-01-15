using Google.Protobuf;
using Grpc.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Crypto;
using Grpc.Net.Client;


namespace Client
{
	internal static class RPC
	{
		public const int ChunkSize = 1024 * 64;

		public static async Task CryptA52(
			AsyncDuplexStreamingCall<A52Request, Chunk> call, 
			string inFilePath, string outFilePath, 
			string key, string iv)
		{
			using FileStream outFileStream = new FileStream(outFilePath, FileMode.Create);

			var request = new A52Request()
			{
				Key = key,
				Iv = iv
			};
			await call.RequestStream.WriteAsync(request);

			await foreach (var (chunk, size) in Helper.ReadFileByChunks(inFilePath, ChunkSize))
			{
				var newRequest = new A52Request()
				{
					Chunk = new Chunk()
					{
						Bytes = ByteString.CopyFrom(chunk),
						Size = size
					}
				};
				await call.RequestStream.WriteAsync(newRequest);

				await call.ResponseStream.MoveNext();
				outFileStream.Write(call.ResponseStream.Current.Bytes.Span);
			}

			await call.RequestStream.CompleteAsync();
		}

		public static async Task EncryptA52(Crypto.Crypto.CryptoClient client, string inFilePath, string outFilePath, string key, string iv)
		{
			await CryptA52(client.EncryptA52(), inFilePath, outFilePath, key, iv);
		}

		public static async Task DecryptA52(Crypto.Crypto.CryptoClient client, string inFilePath, string outFilePath, string key, string iv)
		{
			await CryptA52(client.DecryptA52(), inFilePath, outFilePath, key, iv);
		}

		public static async Task CryptRailFence(
			AsyncDuplexStreamingCall<RailFenceRequest, RailFenceResponse> call,
			string inFilePath, string outFilePath, int rails)
		{
			using StreamWriter writer = new StreamWriter(outFilePath);

			await foreach (string line in Helper.ReadFileByLines(inFilePath))
			{
				var request = new RailFenceRequest()
				{
					Text = line,
					Rails = rails
				};
				await call.RequestStream.WriteAsync(request);

				var response = call.ResponseStream;
				await response.MoveNext();
				writer.WriteLine(response.Current.Text);
			}

			await call.RequestStream.CompleteAsync();
		}

		public static async Task EncryptRailFence(Crypto.Crypto.CryptoClient client, string inFilePath, string outFilePath, int rails)
		{
			await CryptRailFence(client.EncryptRailFence(), inFilePath, outFilePath, rails);
		}

		public static async Task DecryptRailFence(Crypto.Crypto.CryptoClient client, string inFilePath, string outFilePath, int rails)
		{
			await CryptRailFence(client.DecryptRailFence(), inFilePath, outFilePath, rails);
		}
	}
}
