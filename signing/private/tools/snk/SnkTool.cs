// Usage: snk_tool <key.pem> <key.snk> <public.snk>
using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;

using var rsa = RSA.Create();
rsa.ImportFromPem(File.ReadAllText(args[0]));

using var csp = new RSACryptoServiceProvider();
csp.ImportParameters(rsa.ExportParameters(true));
File.WriteAllBytes(args[1], csp.ExportCspBlob(true));

// Match `sn -p`: strong-name header (SigAlgID, HashAlgID, cbPublicKey) followed
// by the PUBLICKEYBLOB, with CALG_RSA_SIGN as the signature/key algorithm.
// ExportCspBlob labels the key CALG_RSA_KEYX, which changes the public key token.
const int CALG_RSA_SIGN = 0x2400;
const int CALG_SHA1 = 0x8004;
var blob = csp.ExportCspBlob(false);
BinaryPrimitives.WriteInt32LittleEndian(blob.AsSpan(4), CALG_RSA_SIGN);
using var output = new BinaryWriter(File.Create(args[2]));
output.Write(CALG_RSA_SIGN);
output.Write(CALG_SHA1);
output.Write(blob.Length);
output.Write(blob);
