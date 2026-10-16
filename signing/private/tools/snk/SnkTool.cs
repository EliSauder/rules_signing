// Usage: snk_tool <key.pem> <key.snk> <public.snk>
using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;

using var rsa = RSA.Create();
rsa.ImportFromPem(File.ReadAllText(args[0]));

using var csp = new RSACryptoServiceProvider();
csp.ImportParameters(rsa.ExportParameters(true));
// ExportCspBlob labels keys CALG_RSA_KEYX; strong-name keys are CALG_RSA_SIGN
// (as `sn -k` writes). Microsoft's `sn -p` keeps the key pair's algorithm, so
// both files need it for the public key token to match.
const int CALG_RSA_SIGN = 0x2400;
const int CALG_SHA1 = 0x8004;
var keyPair = csp.ExportCspBlob(true);
BinaryPrimitives.WriteInt32LittleEndian(keyPair.AsSpan(4), CALG_RSA_SIGN);
File.WriteAllBytes(args[1], keyPair);

// Match `sn -p`: strong-name header (SigAlgID, HashAlgID, cbPublicKey) followed
// by the PUBLICKEYBLOB.
var blob = csp.ExportCspBlob(false);
BinaryPrimitives.WriteInt32LittleEndian(blob.AsSpan(4), CALG_RSA_SIGN);
using var output = new BinaryWriter(File.Create(args[2]));
output.Write(CALG_RSA_SIGN);
output.Write(CALG_SHA1);
output.Write(blob.Length);
output.Write(blob);
