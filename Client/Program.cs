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

Console.WriteLine("A52");
string keyA52 = "1100111010100101111010011101100001110111000011101011100011111110";
string ivA52 = "0010110100100001001111";
await RPC.EncryptA52(client, "Resources\\binary.bin", "bynary_e.bin", keyA52, ivA52);
await RPC.DecryptA52(client, "bynary_e.bin", "bynary_d.bin", keyA52, ivA52);
Console.WriteLine(await RPC.ComputeMD5Hash(client, "Resources\\binary.bin"));
Console.WriteLine(await RPC.ComputeMD5Hash(client, "bynary_d.bin"));
Console.WriteLine();

Console.WriteLine("RailFence");
await RPC.EncryptRailFence(client, "Resources\\rf.txt", "rf_e.txt", 3);
await RPC.DecryptRailFence(client, "rf_e.txt", "rf_d.txt", 3);
Console.WriteLine(await RPC.ComputeMD5Hash(client, "Resources\\rf.txt"));
Console.WriteLine(await RPC.ComputeMD5Hash(client, "rf_d.txt"));
Console.WriteLine();

Console.WriteLine("XTEA");
await RPC.EncryptXTEA(client, "Resources\\nighthawks.jpg", "nighthawks_e", "1254512389401236");
await RPC.DecryptXTEA(client, "nighthawks_e", "nighthawks_d.jpg", "1254512389401236");
Console.WriteLine(await RPC.ComputeMD5Hash(client, "Resources\\nighthawks.jpg"));
Console.WriteLine(await RPC.ComputeMD5Hash(client, "nighthawks_d.jpg"));
Console.WriteLine();

Console.WriteLine("XTEA With PCBC");
await RPC.EncryptXTEAPCBC(client, "Resources\\test", "test_e", "1254512389401236", "23471322");
await RPC.DecryptXTEAPCBC(client, "test_e", "test_d", "1254512389401236", "23471322");
Console.WriteLine(await RPC.ComputeMD5Hash(client, "Resources\\test"));
Console.WriteLine(await RPC.ComputeMD5Hash(client, "test_d"));
Console.WriteLine();

Console.WriteLine("BMP image with XTEA");
await RPC.EncryptBMPImage(client, "Resources\\img.bmp", "img_e.bmp", keyA52, ivA52);
await RPC.DecryptBMPImage(client, "img_e.bmp", "img_d.bmp", keyA52, ivA52);
Console.WriteLine(await RPC.ComputeMD5Hash(client, "Resources\\img.bmp"));
Console.WriteLine(await RPC.ComputeMD5Hash(client, "img_d.bmp"));
Console.WriteLine();

Console.WriteLine("XTEA Parallel");
await RPC.EncryptXTEAParallel(client, "Resources\\nighthawks.jpg", "nighthawks_p_e", "1254512389401236", 4);
await RPC.DecryptXTEAParallel(client, "nighthawks_p_e", "nighthawks_p_d.jpg", "1254512389401236", 4);
Console.WriteLine(await RPC.ComputeMD5Hash(client, "Resources\\nighthawks.jpg"));
Console.WriteLine(await RPC.ComputeMD5Hash(client, "nighthawks_p_d.jpg"));
Console.WriteLine();

Console.WriteLine("Press any key to exit...");
Console.ReadKey();

