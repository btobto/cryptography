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

await RPC.EncryptRailFence(client, "railfence_original.txt", "railfence_encrypted.txt", 3);
await RPC.DecryptRailFence(client, "railfence_encrypted.txt", "railfence_decrypted.txt", 3);

await RPC.EncryptXTEA(client, "railfence_original.txt", "lotr_en.txt", "1254512389401236");
await RPC.DecryptXTEA(client, "lotr_en.txt", "lotr_de.txt", "1254512389401236");

await RPC.EncryptXTEA(client, "nighthawks.jpg", "ng_en", "1254512389401236");
await RPC.DecryptXTEA(client, "ng_en", "nh_de.jpg", "1254512389401236");

await RPC.EncryptXTEA(client, "test", "test_en", "1254512389401236");
await RPC.DecryptXTEA(client, "test_en", "test_de", "1254512389401236");



Console.WriteLine("Press any key to exit...");
Console.ReadKey();

