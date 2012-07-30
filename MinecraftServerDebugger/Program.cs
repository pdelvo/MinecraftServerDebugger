using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Pdelvo.Minecraft.Network;
using Pdelvo.Minecraft.Protocol;
using Pdelvo.Minecraft.Protocol.Packets;

namespace MinecraftServerDebugger
{
    class Program
    {
        static RSAKeyPair _keyPair;

        static void Main(string[] args)
        {
            Console.WriteLine("Starting server debugger");

            if (args.Length < 1)
            {
                Console.WriteLine("Minecraft Login Debugger: -debug|-d MinecraftServerDebugger.exe [Port]");
                Console.WriteLine("Asynchronous key test kit: -encryptionTestKit|-etk [filename]");
                return;
            }
            Console.WriteLine("Generating Rsa Key Pair...");
            _keyPair = ProtocolSecurity.GenerateRSAKeyPair();
            Console.WriteLine("Keypair generated");
            switch (args[0])
            {
                case "-debug":
                case "-d":
                    if (args.Length < 2)
                        Console.WriteLine("Port missing");
                    else
                        WaitForClient(int.Parse(args[1]));
                    break;
                case "-encryptionTestKit":
                case "-etk":
                    string path = args.Length < 2 ? "keys.txt" : args[1];

                    using (TextWriter stream = new StreamWriter(File.Create(path)))
                    {
                        stream.WriteLine("Private RSA Key: " + FormatArray(_keyPair.GetPrivate()));
                        stream.WriteLine("Public RSA Key: " + FormatArray(_keyPair.GetPublic()));
                        stream.WriteLine("------------------------------------------------------");
                        byte[] randomBuffer = new byte[4];
                        new Random().NextBytes(randomBuffer);

                        stream.WriteLine("Demo verification token: " + FormatArray(randomBuffer));
                        stream.WriteLine("Public key encrypted verification token: " + FormatArray(ProtocolSecurity.RSAEncrypt(randomBuffer, _keyPair.GetPublic(), false)));
                        using (ConsoleHelpers.ChangeForegroundColor(ConsoleColor.Green))
                            Console.WriteLine("Finished");
                    }

                    break;
                default:
                    Console.WriteLine("Unknown parameter");
                    break;
            }
            


            Console.WriteLine("Press Any Key to exit");
            Console.ReadKey(true);
        }

        private static async void WaitForClient(int port)
        {
            TcpListener listener = new TcpListener(new IPEndPoint(IPAddress.Any, port));
            try
            {
                listener.Start();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Could not bind to the specific port" + Environment.NewLine + ex.ToString());
                Environment.Exit(1);
                return;
            }

            while (true)
            {
                bool error = false;
                Console.WriteLine("Waiting for a client to connect at " + listener.LocalEndpoint.ToString());
                var client = await listener.AcceptTcpClientAsync();

                Console.WriteLine("Client connected");

                using (ConsoleHelpers.ChangeForegroundColor(ConsoleColor.Magenta))
                Console.WriteLine("Waiting for Handshake Request (0x02)");

                var clientRemoteInterface = new ClientRemoteInterface(
    new BigEndianStream(
        new FullyReadStream(
            client.GetStream())), 39);

                var packet = clientRemoteInterface.ReadPacket();

                if (packet is PlayerListPing)
                {
                    Console.WriteLine("Server list Ping (0xFE) received. answering...");
                    await clientRemoteInterface.SendPacketAsync(new DisconnectPacket { Reason = "Minecraft Client Debug Server§0§1" });
                    client.Close();
                    continue;
                }
                else if (packet is HandshakeRequest)
                {
                    var handshakePacket = packet as HandshakeRequest;
                    using (ConsoleHelpers.ChangeForegroundColor(ConsoleColor.Green))
                    {
                        Console.WriteLine("<Handshake packet>");
                        error = error || !Test(" Username: " + handshakePacket.UserName, handshakePacket.UserName.Length < 16, "Username out of range");
                        Console.WriteLine(" Host: " + handshakePacket.Host);
                        error = error || !Test(" Protocol Version: " + handshakePacket.ProtocolVersion, handshakePacket.ProtocolVersion == 39, "Protocol Version missmatch");
                        Console.WriteLine("</Handshake packet>");
                    }

                    if (error)
                    {
                        await clientRemoteInterface.SendPacketAsync(new DisconnectPacket { Reason = "0x02 expected" });
                        client.Close();
                        continue;
                    }
                    byte[] randomBuffer = new byte[4];
                    new Random().NextBytes(randomBuffer);
                    var buffer = new byte[4];
                    new Random().NextBytes(buffer);
                    //buffer = MD5.Create().ComputeHash(buffer);
                    buffer[0] = 42;
                    var serverId = BitConverter.ToString(buffer).Replace("-", "").ToLower();

                    var encryptionRequest = new EncryptionKeyRequest
                    {
                        ServerId = serverId,
                        PublicKey = _keyPair.GetPublic(),
                        VerifyToken = randomBuffer
                    };

                    using (ConsoleHelpers.ChangeForegroundColor(ConsoleColor.Yellow))
                    {
                        Console.WriteLine("<Handshake response packet>");
                        Console.WriteLine(" ServerId: " + serverId);
                        Console.WriteLine(" Public Key: " + BitConverter.ToString(_keyPair.GetPublic()).Replace("-", "").ToLower());
                        Console.WriteLine(" VerifyToken: " + BitConverter.ToString(randomBuffer).Replace("-", "").ToLower());
                        Console.WriteLine("</Handshake response packet>");
                    }

                    await clientRemoteInterface.SendPacketAsync(encryptionRequest);

                    using (ConsoleHelpers.ChangeForegroundColor(ConsoleColor.Magenta))
                        Console.WriteLine("Waiting for 0xFC Encryption response packet");

                    packet = clientRemoteInterface.ReadPacket();

                    if (packet is EncryptionKeyResponse)
                    {
                        var encryptionKeyResponse = packet as EncryptionKeyResponse;
                        Console.WriteLine("<Encryption key response packet>");
                        Console.WriteLine(" Shared Key: " + FormatArray(encryptionKeyResponse.SharedKey.ToArray()));
                        Console.WriteLine(" Verify Token: " + FormatArray(encryptionKeyResponse.VerifyToken.ToArray()));
                        Console.WriteLine("</Encryption key response packet>");

                        Console.WriteLine("Decryption Verify Token");
                        var verification = Pdelvo.Minecraft.Network.ProtocolSecurity.RSADecrypt(encryptionKeyResponse.VerifyToken.ToArray(), _keyPair.GetPrivate(), true);
                        error = error || Test("Received Verify Token: " + FormatArray(verification),
                            verification.Length == randomBuffer.Length
                          && verification.Zip(randomBuffer, (a, b) => a == b).All(a => a), "Verification Token missmatch");


                        if (error)
                        {

                            using (ConsoleHelpers.ChangeForegroundColor(ConsoleColor.Red))
                            {
                                Console.WriteLine("Verfiy Token was not encrypted correctly");
                                if (verification.Length == randomBuffer.Length
                          && verification.Zip(randomBuffer, (a, b) => a == b).All(a => a))
                                {
                                    Console.WriteLine("The provided verify token is the one sended to the server, which is not correct. the token must be encrypted using the rsa public key in the handshake packet.");
                                }
                            }
                            await clientRemoteInterface.SendPacketAsync(new DisconnectPacket { Reason = "Verify Token missmatch" });
                            client.Close();
                            continue;
                        }

                        Console.WriteLine("Decrypting aes key...");

                        byte[] encryptedKey = encryptionKeyResponse.SharedKey.ToArray();
                        var decrypt = Pdelvo.Minecraft.Network.ProtocolSecurity.RSADecrypt(encryptedKey, _keyPair.GetPrivate(), true);

                        //using(ConsoleHelpers.ChangeForegroundColor(ConsoleColor.Green))
                        //    Console.WriteLine("Received shared key: " + );
                    }
                    else
                    {
                        error = true;
                        Console.WriteLine("Invalid packet received. 0xFC expected. Packet was " + packet.ToString());
                        await clientRemoteInterface.SendPacketAsync(new DisconnectPacket { Reason = "0x02 expected" });
                        client.Close();
                        continue;
                    }

                }
                else
                {
                    error = true;
                    Console.WriteLine("Invalid packet received. 0x02 expected. Packet was " + packet.ToString());
                    await clientRemoteInterface.SendPacketAsync(new DisconnectPacket { Reason = "0x02 expected" });
                    client.Close();
                    continue;
                }
            }
        }

        static bool Test(string logMessage, bool func, string errorMessage)
        {
            bool result = func;

            using (ConsoleHelpers.ChangeForegroundColor(result ? ConsoleColor.Green : ConsoleColor.Red))
            {
                Console.WriteLine(logMessage);

                if (!result) Console.WriteLine(errorMessage);
            }
            return result;
        }
        static bool Test(string logMessage, Func<bool> func, string errorMessage)
        {
            return Test(logMessage, func(), errorMessage);
        }

        static string FormatArray(byte[] array)
        {
            return BitConverter.ToString(array).Replace("-", "").ToLower();
        }
    }

    static class ConsoleHelpers
    {
        public static IDisposable ChangeForegroundColor(ConsoleColor color)
        {
            var disposer = new ConsoleForegroundColorDisposer(Console.ForegroundColor);
            Console.ForegroundColor = color;
            return disposer;
        }

        class ConsoleForegroundColorDisposer : IDisposable
        {
            ConsoleColor _oldColor;

            public ConsoleForegroundColorDisposer(ConsoleColor oldColor)
            {
                _oldColor = oldColor;
            }

            public void Dispose()
            {
                Console.ForegroundColor = _oldColor;
            }
        }

    }
}
