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

			var responseTask = Task.Run(async () =>
			{
				await foreach (var response in call.ResponseStream.ReadAllAsync())
				{
					outFileStream.Write(response.Bytes.Span);
				}
			});

			await foreach (var (chunk, size) in Helper.ReadFileByChunks(inFilePath, ChunkSize))
			{
				var newRequest = new A52Request()
				{
					Chunk = new Chunk()
					{
						Bytes = ByteString.CopyFrom(chunk, 0, size)
					}
				};
				await call.RequestStream.WriteAsync(newRequest);
			}

			await call.RequestStream.CompleteAsync();
			await responseTask;
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

			var responseTask = Task.Run(async () =>
			{
				await foreach (var response in call.ResponseStream.ReadAllAsync())
				{
					writer.WriteLine(response.Text);
				}
			});

			await foreach (string line in Helper.ReadFileByLines(inFilePath))
			{
				var request = new RailFenceRequest()
				{
					Text = line,
					Rails = rails
				};
				await call.RequestStream.WriteAsync(request);
			}

			await call.RequestStream.CompleteAsync();
			await responseTask;
		}

		public static async Task EncryptRailFence(Crypto.Crypto.CryptoClient client, string inFilePath, string outFilePath, int rails)
		{
			await CryptRailFence(client.EncryptRailFence(), inFilePath, outFilePath, rails);
		}

		public static async Task DecryptRailFence(Crypto.Crypto.CryptoClient client, string inFilePath, string outFilePath, int rails)
		{
			await CryptRailFence(client.DecryptRailFence(), inFilePath, outFilePath, rails);
		}

		public static async Task CryptXTEA(
			AsyncDuplexStreamingCall<XTEARequest, Chunk> call, 
			string inFilePath, string outFilePath,
			string key)
		{
			using FileStream outFileStream = new FileStream(outFilePath, FileMode.Create);

			var request = new XTEARequest() { Key = key };
			await call.RequestStream.WriteAsync(request);

			var responseTask = Task.Run(async () =>
			{
				await foreach (var response in call.ResponseStream.ReadAllAsync())
				{
					outFileStream.Write(response.Bytes.Span);
				}
			});

			await foreach (var (chunk, size) in Helper.ReadFileByChunks(inFilePath, ChunkSize))
			{
				request = new XTEARequest()
				{
					Chunk = new Chunk() { 
						Bytes = ByteString.CopyFrom(chunk, 0, size)
					}
				};
				await call.RequestStream.WriteAsync(request);
			}

			await call.RequestStream.CompleteAsync();
			await responseTask;
		}

		public static async Task EncryptXTEA(Crypto.Crypto.CryptoClient client, string inFilePath, string outFilePath, string key)
		{
			await CryptXTEA(client.EncryptXTEA(), inFilePath, outFilePath, key);
		}

		public static async Task DecryptXTEA(Crypto.Crypto.CryptoClient client, string inFilePath, string outFilePath, string key)
		{
			await CryptXTEA(client.DecryptXTEA(), inFilePath, outFilePath, key);
		}

		public static async Task CryptXTEAPCBC(
			AsyncDuplexStreamingCall<XTEAPCBCRequest, Chunk> call,
			string inFilePath, string outFilePath,
			string key, string iv)
		{
			using FileStream outFileStream = new FileStream(outFilePath, FileMode.Create);

			var request = new XTEAPCBCRequest() { Key = key, Iv = iv };
			await call.RequestStream.WriteAsync(request);

			var responseTask = Task.Run(async () =>
			{
				await foreach (var response in call.ResponseStream.ReadAllAsync())
				{
					outFileStream.Write(response.Bytes.Span);
				}
			});

			await foreach (var (chunk, size) in Helper.ReadFileByChunks(inFilePath, ChunkSize))
			{
				request = new XTEAPCBCRequest()
				{
					Chunk = new Chunk()
					{
						Bytes = ByteString.CopyFrom(chunk, 0, size)
					}
				};
				await call.RequestStream.WriteAsync(request);
			}

			await call.RequestStream.CompleteAsync();
			await responseTask;
		}

		public static async Task EncryptXTEAPCBC(Crypto.Crypto.CryptoClient client, string inFilePath, string outFilePath, string key, string iv)
		{
			await CryptXTEAPCBC(client.EncryptXTEAPCBC(), inFilePath, outFilePath, key, iv);
		}

		public static async Task DecryptXTEAPCBC(Crypto.Crypto.CryptoClient client, string inFilePath, string outFilePath, string key, string iv)
		{
			await CryptXTEAPCBC(client.DecryptXTEAPCBC(), inFilePath, outFilePath, key, iv);
		}

		public static async Task<string> ComputeMD5Hash(Crypto.Crypto.CryptoClient client, string inFilePath)
		{
			var call = client.ComputeMD5Hash();

			await foreach (var (chunk, size) in Helper.ReadFileByChunks(inFilePath, ChunkSize))
			{
				var request = new Chunk()
				{
					Bytes = ByteString.CopyFrom(chunk, 0, size)
				};
				await call.RequestStream.WriteAsync(request);
			}

			await call.RequestStream.CompleteAsync();

			MD5Response result = await call;
			return result.Hash;
		}

		public static async Task CryptBMPImage(AsyncDuplexStreamingCall<A52Request, Chunk> call, string inFilePath, string outFilePath, string key, string iv)
		{
			using FileStream outFileStream = new FileStream(outFilePath, FileMode.Create);

			var headerReader = Helper.ReadFileByChunks(inFilePath, 54).GetAsyncEnumerator();
			await headerReader.MoveNextAsync();
			byte[] header = headerReader.Current.Item1;
			await headerReader.DisposeAsync();

			outFileStream.Write(header);

			var request = new A52Request()
			{
				Key = key,
				Iv = iv
			};
			await call.RequestStream.WriteAsync(request);

			var responseTask = Task.Run(async () =>
			{
				await foreach (var response in call.ResponseStream.ReadAllAsync())
				{
					outFileStream.Write(response.Bytes.Span);
				}
			});

			await foreach (var (chunk, size) in Helper.ReadFileByChunks(inFilePath, ChunkSize, 54))
			{
				request = new A52Request()
				{
					Chunk = new Chunk()
					{
						Bytes = ByteString.CopyFrom(chunk, 0, size)
					}
				};
				await call.RequestStream.WriteAsync(request);
			}

			await call.RequestStream.CompleteAsync();
			await responseTask;

		}

		public static async Task EncryptBMPImage(Crypto.Crypto.CryptoClient client, string inFilePath, string outFilePath, string key, string iv)
		{
			await CryptBMPImage(client.EncryptA52(), inFilePath, outFilePath, key, iv);
		}

		public static async Task DecryptBMPImage(Crypto.Crypto.CryptoClient client, string inFilePath, string outFilePath, string key, string iv)
		{
			await CryptBMPImage(client.DecryptA52(), inFilePath, outFilePath, key, iv);
		}
	}
}

