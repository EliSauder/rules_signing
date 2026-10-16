// Writes .NET strong-name key files (.snk) from an RSA private key in PEM form.
//
// Usage: snk_tool --in <key.pem> --out <key.snk> [--public-out <public.snk>]
//                 [--password-env <VAR>]
using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;

internal static class SnkTool
{
    // Strong-name public key header: SigAlgId (CALG_RSA_SIGN), HashAlgId
    // (CALG_SHA1) and the byte length of the PUBLICKEYBLOB that follows.
    private const uint CalgRsaSign = 0x2400;
    private const uint CalgSha1 = 0x8004;

    // .NET marks exported blobs as key-exchange keys (CALG_RSA_KEYX); `sn`
    // writes strong-name keys as signature keys, so match it.
    private static void SetSignatureAlgorithm(byte[] blob)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(4, 4), CalgRsaSign);
    }

    private static int Main(string[] args)
    {
        string input = null, output = null, publicOutput = null, passwordEnv = null;
        for (int i = 0; i + 1 < args.Length; i += 2)
        {
            switch (args[i])
            {
                case "--in": input = args[i + 1]; break;
                case "--out": output = args[i + 1]; break;
                case "--public-out": publicOutput = args[i + 1]; break;
                case "--password-env": passwordEnv = args[i + 1]; break;
                default:
                    Console.Error.WriteLine($"snk_tool: unknown argument {args[i]}");
                    return 2;
            }
        }
        if (input == null || output == null)
        {
            Console.Error.WriteLine("usage: snk_tool --in <key.pem> --out <key.snk> [--public-out <public.snk>] [--password-env <VAR>]");
            return 2;
        }

        using var rsa = RSA.Create();
        try
        {
            string pem = File.ReadAllText(input);
            if (pem.Contains("ENCRYPTED PRIVATE KEY"))
            {
                string password = passwordEnv == null ? "" : Environment.GetEnvironmentVariable(passwordEnv) ?? "";
                rsa.ImportFromEncryptedPem(pem, password);
            }
            else
            {
                rsa.ImportFromPem(pem);
            }
        }
        catch (Exception e) when (e is CryptographicException || e is ArgumentException)
        {
            Console.Error.WriteLine($"snk_tool: strong-name keys must be RSA, but no RSA private key could be read from {input}: {e.Message}");
            return 1;
        }

        // The CSP blob format is exactly what an .snk holds. ExportCspBlob is
        // pure parameter encoding, so it works on every platform.
        using var csp = new RSACryptoServiceProvider();
        csp.ImportParameters(rsa.ExportParameters(true));
        byte[] pair = csp.ExportCspBlob(true);
        SetSignatureAlgorithm(pair);
        File.WriteAllBytes(output, pair);

        if (publicOutput != null)
        {
            byte[] blob = csp.ExportCspBlob(false);
            SetSignatureAlgorithm(blob);
            byte[] key = new byte[12 + blob.Length];
            BinaryPrimitives.WriteUInt32LittleEndian(key.AsSpan(0, 4), CalgRsaSign);
            BinaryPrimitives.WriteUInt32LittleEndian(key.AsSpan(4, 4), CalgSha1);
            BinaryPrimitives.WriteUInt32LittleEndian(key.AsSpan(8, 4), (uint)blob.Length);
            blob.CopyTo(key, 12);
            File.WriteAllBytes(publicOutput, key);
        }
        return 0;
    }
}
