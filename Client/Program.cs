using Client;
using Crypto;
using Google.Protobuf;
using Grpc.Core;
using Grpc.Net.Client;
using System.Collections;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Reflection;
using System.Text;


using var channel = GrpcChannel.ForAddress("https://localhost:7186");
var client = new Crypto.Crypto.CryptoClient(channel);
//var reply = await client.SayHelloAsync(new HelloRequest { Name = "GreeterClient" });
//Console.WriteLine("Greeting: " + reply.Message);

string filesDir = AppDomain.CurrentDomain.BaseDirectory;

string keyA52 = "1100111010100101111010011101100001110111000011101011100011111110";
string ivA52 = "0010110100100001001111";
await RPC.EncryptA52(
	client, 
	Path.Combine(filesDir, "a52_original.bin"),
	Path.Combine(filesDir, "a52_encrypted.bin"),
	keyA52, ivA52
);
await RPC.DecryptA52(
	client,
	Path.Combine(filesDir, "a52_encrypted.bin"),
	Path.Combine(filesDir, "a52_decrypted.bin"),
	keyA52, ivA52
);

Console.WriteLine("Press any key to exit...");
Console.ReadKey();

