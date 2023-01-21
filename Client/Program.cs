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

string filesDir = AppDomain.CurrentDomain.BaseDirectory;
Console.WriteLine("Files location:");
Console.WriteLine(filesDir);
Console.WriteLine();

Console.WriteLine("A52");
string keyA52 = "1100111010100101111010011101100001110111000011101011100011111110";
string ivA52 = "0010110100100001001111";
string original1 = "Resources\\binary.bin", encrypted1 = "bynary_encrypted.bin", decrypted1 = "bynary_decrypted.bin";
await RPC.EncryptA52(client, original1, encrypted1, keyA52, ivA52);
await RPC.DecryptA52(client, encrypted1, decrypted1, keyA52, ivA52);
await CompareMD5Hashes(client, original1, decrypted1);

Console.WriteLine("RailFence");
string original2 = "Resources\\rf.txt", encrypted2 = "rf_encrypted.txt", decrypted2 = "rf_decrypted.txt";
await RPC.EncryptRailFence(client, original2, encrypted2, 3);
await RPC.DecryptRailFence(client, encrypted2, decrypted2, 3);
await CompareMD5Hashes(client, original2, decrypted2);

Console.WriteLine("XTEA");
string original3 = "Resources\\nighthawks.jpg", encrypted3 = "nh_encrypted", decrypted3 = "nh_decrypted.jpg";
await RPC.EncryptXTEA(client, original3, encrypted3, "1254512389401236");
await RPC.DecryptXTEA(client, encrypted3, decrypted3, "1254512389401236");
await CompareMD5Hashes(client, original3, decrypted3);

Console.WriteLine("XTEA With PCBC");
string original4 = "Resources\\test", encrypted4 = "test_encrypted", decrypted4 = "test_decrypted";
await RPC.EncryptXTEAPCBC(client, original4, encrypted4, "1254512389401236", "23471322");
await RPC.DecryptXTEAPCBC(client, encrypted4, decrypted4, "1254512389401236", "23471322");
await CompareMD5Hashes(client, original4, decrypted4);

Console.WriteLine("BMP image with XTEA");
string original5 = "Resources\\img.bmp", encrypted5 = "img_encrypted.bmp", decrypted5 = "img_decrypted.bmp.jpg";
await RPC.EncryptBMPImage(client, original5, encrypted5, keyA52, ivA52);
await RPC.DecryptBMPImage(client, encrypted5, decrypted5, keyA52, ivA52);
await CompareMD5Hashes(client, original5, decrypted5);

Console.WriteLine("XTEA Parallel");
string original6 = "Resources\\nighthawks.jpg", encrypted6 = "nh_p_encrypted", decrypted6 = "nh_p_decrypted.jpg";
await RPC.EncryptXTEAParallel(client, original6, encrypted6, "1254512389401236", 4);
await RPC.DecryptXTEAParallel(client, encrypted6, decrypted6, "1254512389401236", 4);
await CompareMD5Hashes(client, original6, decrypted6);

Console.WriteLine("Press any key to exit...");
Console.ReadKey();

async Task CompareMD5Hashes(Crypto.Crypto.CryptoClient client, string file1, string file2)
{
	string hash1 = await RPC.ComputeMD5Hash(client, file1);
	string hash2 = await RPC.ComputeMD5Hash(client, file2);

	Console.WriteLine($"FILE: {file1}:");
	Console.WriteLine(hash1);
	Console.WriteLine($"FILE: {file2}:");
	Console.WriteLine(hash2);

	if (hash1 == hash2) Console.WriteLine("Hashes match.");
	else Console.WriteLine("Hashes DON'T match.");

	Console.WriteLine();
}