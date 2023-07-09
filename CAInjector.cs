using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace MyHttpProxy;

public abstract class CaInjector
{
    /// <summary>
    /// Validates if the CA is injected, and injects it otherwise.
    /// </summary>
    public static void ValidateOrInject()
    {
        if (ValidateCaInjected())
        {
            Console.WriteLine("[CA IS ALREADY INJECTED]");
            return;
        }
        InjectCa();
    }

    /// <summary>
    /// Returns the Private Key of the injected CA. If missing, re-injects.
    /// </summary>
    public static string RetrievePrivateKey()
    {
        if (File.Exists(CaPrivateKeyPath))
        {
            Console.WriteLine($"[CA PRIVATE KEY FOUND]: {CaPrivateKeyPath}");
            return File.ReadAllText(CaPrivateKeyPath);
        }
        
        // if private key is missing but we want to retrieve it
        // then it's likely the CWD changed or the file was removed.
        // re-inject, and try again.
        Console.WriteLine("[CA PRIVATE KEY NOT FOUND]");
        InjectCa();

        return RetrievePrivateKey();
    }

    /// <summary>
    /// Returns the pem certificate of the injected CA. If missing, re-injects.
    /// </summary>
    public static string RetrieveCertificate()
    {
        if (File.Exists(CaCertificatePath))
        {
            Console.WriteLine($"[CA CERTIFICATE FOUND]: {CaCertificatePath}");
            return File.ReadAllText(CaCertificatePath);
        }

        // if certificate is missing but we want to retrieve it
        // then it's likely the CWD changed or the file was removed.
        // re-inject, and try again.
        Console.WriteLine("[CA CERTIFICATE NOT FOUND]");
        InjectCa();

        return RetrieveCertificate();
    }
    
    private const string CaFileName = "MyDummyInjectedCA.crt";
    private const string CaPrivateKeyFileName = "CAPrivateKey.key";
    private static readonly string CaCertificatePath = GetCertificatePath();
    private static readonly string CaPrivateKeyPath = GetPrivateKeyPath();
    
    private static void InjectCa()
    {
        Console.WriteLine($"[INJECTING ROOT CA]: {CaCertificatePath}");

        var (privateKey, certificateText) = CertificateGeneration
            .CreateCertificateAuthority();

        // store the private key
        File.WriteAllText(CaPrivateKeyPath, privateKey);
        Console.WriteLine($"[STORING CA PRIVATE KEY]: {CaPrivateKeyPath}");
        
        if (SystemIdentifier.GatheredInformation.OsPlatform == 
            OSPlatform.Linux)
        {
            if (SystemIdentifier.GatheredInformation.OsFlavor ==
                SystemInformation.OSFlavor.ARCH)
            {
                File.WriteAllText(CaCertificatePath, certificateText);
                Process.Start("trust", "extract-compat").WaitForExit();
                return;
            }
            
            // non-arch distros use this
            File.WriteAllText(CaCertificatePath, certificateText);
            Process.Start("update-ca-certificates").WaitForExit();
        }
        if (SystemIdentifier.GatheredInformation.OsPlatform ==
            OSPlatform.Windows)
        {
            // delete the CA if it exist (just in case)
            CommandExecutor.ExecuteCommand("certutil", $"-delstore \"Root\" \"{
                    CertificateGeneration.CaCommonName}\"");

            // store the certificate
            File.WriteAllText(CaCertificatePath, certificateText);
            
            // add the newly stored CA as root
            CommandExecutor.ExecuteCommand("certutil", $"-addstore \"Root\" \"{
                CaCertificatePath}\"");
        }
        if (SystemIdentifier.GatheredInformation.OsPlatform ==
            OSPlatform.OSX)
        {
            // todo:
        }
    }
    
    private static bool ValidateCaInjected()
    {
        if (SystemIdentifier.GatheredInformation.OsPlatform == 
            OSPlatform.Linux)
        {
            if (SystemIdentifier.GatheredInformation.OsFlavor ==
                SystemInformation.OSFlavor.ARCH)
            {
                return File.Exists(CaCertificatePath);
            }
            return File.Exists(CaCertificatePath);
        }
        if (SystemIdentifier.GatheredInformation.OsPlatform ==
                 OSPlatform.Windows)
        {
            var output = CommandExecutor.ExecuteCommand("certutil",
                $"-verifystore \"Root\" \"{
                    CertificateGeneration.CaCommonName}\"");
            return output.Contains(CertificateGeneration.CaCommonName);
        }
        if (SystemIdentifier.GatheredInformation.OsPlatform ==
                 OSPlatform.OSX)
        {
            // todo:
        }

        // unreachable
        return true;
    }

    private static string GetPrivateKeyPath()
    {
        // todo: change this to temp folder.
        return Path.Join(Directory.GetCurrentDirectory(),
            CaPrivateKeyFileName);
    }
    
    private static string GetCertificatePath()
    {
        if (SystemIdentifier.GatheredInformation.OsPlatform == 
            OSPlatform.Linux)
        {
            if (SystemIdentifier.GatheredInformation.OsFlavor ==
                SystemInformation.OSFlavor.ARCH)
            {
                return Path.Join("/etc/ca-certificates/trust-source/anchors/",
                    CaFileName);
            }
            return Path.Join("/usr/local/share/ca-certificates/",
                CaFileName);
        }
        if (SystemIdentifier.GatheredInformation.OsPlatform ==
            OSPlatform.Windows)
        {
            // todo: should be temp folder
            return Path.Join(Directory.GetCurrentDirectory(), CaFileName);
        }
        if (SystemIdentifier.GatheredInformation.OsPlatform ==
            OSPlatform.OSX)
        {
            // todo:
        }

        throw new Exception("Could not get the certificate path!");
    }
}