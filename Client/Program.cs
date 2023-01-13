using Crypto;
using Google.Protobuf;
using Grpc.Core;
using Grpc.Net.Client;
using System.Collections;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Reflection;
using System.Text;

const int ChunkSize = 1024 * 64;

using var channel = GrpcChannel.ForAddress("https://localhost:7186");
var client = new Crypto.Crypto.CryptoClient(channel);
//var reply = await client.SayHelloAsync(new HelloRequest { Name = "GreeterClient" });
//Console.WriteLine("Greeting: " + reply.Message);

string filesDir = AppDomain.CurrentDomain.BaseDirectory;

string keyA52 = "1100111010100101111010011101100001110111000011101011100011111110";
string ivA52 = "0010110100100001001111";
await EncryptA52(
	client, 
	Path.Combine(filesDir, "a52_original.bin"),
	Path.Combine(filesDir, "a52_encrypted.bin"),
	keyA52, ivA52
);

await DecryptA52(
	client,
	Path.Combine(filesDir, "a52_encrypted.bin"),
	Path.Combine(filesDir, "a52_decrypted.bin"),
	keyA52, ivA52
);

Console.WriteLine("Press any key to exit...");
Console.ReadKey();

async IAsyncEnumerable<(byte[], int)> ReadChunkFromFile(string filePath)
{
	using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
	{
		var chunk = new byte[ChunkSize];
		int bytesRead;
		while ((bytesRead = await stream.ReadAsync(chunk, 0, chunk.Length)) > 0)
		{
			yield return (chunk, bytesRead);
		}
	}
}

async Task EncryptA52(Crypto.Crypto.CryptoClient client, string inFilePath, string outFilePath, string key, string iv)
{
	var call = client.EncryptA52();

	using FileStream outFileStream = new FileStream(outFilePath, FileMode.Create);

	var request = new A52Request()
	{
		Key = key,
		Iv = iv
	};
	await call.RequestStream.WriteAsync(request);

	await foreach (var (chunk, size) in ReadChunkFromFile(inFilePath))
	{
		var newRequest = new A52Request()
		{
			Chunk = new Chunk() { 
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

async Task DecryptA52(Crypto.Crypto.CryptoClient client, string inFilePath, string outFilePath, string key, string iv)
{
	var call = client.DecryptA52();

	using FileStream outFileStream = new FileStream(outFilePath, FileMode.Create);

	var request = new A52Request()
	{
		Key = key,
		Iv = iv
	};
	await call.RequestStream.WriteAsync(request);

	await foreach (var (chunk, size) in ReadChunkFromFile(inFilePath))
	{
		var newRequest = new A52Request()
		{
			Chunk = new Chunk() { 
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