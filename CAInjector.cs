using System.Diagnostics;
using System.Runtime.InteropServices;

namespace MyHttpProxy;

public abstract class CAInjector
{
    private const string CA_FILE_NAME = "DummyInjectedCA.crt";
    private const string CA_PRIVATE_KEY_FILE_NAME = "CAPrivateKey.key";
    
    public static void ValidateOrInject()
    {
        if (ValidateCaInjected())
        {
            return;
        }
        InjectCa();
    }

    public static string RetrievePrivateKey()
    {
        var privateKeyPath = Path.Join(Directory.GetCurrentDirectory(),
            CA_PRIVATE_KEY_FILE_NAME);

        if (File.Exists(privateKeyPath))
        {
            return File.ReadAllText(privateKeyPath);
        }
        
        // if private key is missing but we want to retrieve it
        // then it's likely the CWD changed or the file was removed.
        // re-inject, and try again.
        InjectCa();

        return RetrievePrivateKey();
    }
    
    private static void InjectCa()
    {
        var (
            privateKey, 
            certificateText) = CertificateGeneration.GenerateCaKeyPair();

        // store the private key
        File.WriteAllText(Path.Join(Directory.GetCurrentDirectory(), 
            CA_PRIVATE_KEY_FILE_NAME), privateKey);
        
        string certificatePath;
        
        if (SystemIdentifier.GatheredInformation.OsPlatform == 
            OSPlatform.Linux)
        {
            if (SystemIdentifier.GatheredInformation.OsFlavor ==
                SystemInformation.OSFlavor.ARCH)
            {
                certificatePath = Path.Join(
                    "/etc/ca-certificates/trust-source/anchors/",
                    CA_FILE_NAME);
                File.WriteAllText(certificatePath, certificateText);
                Process.Start("trust", "extract-compat").WaitForExit();
                return;
            }
            
            // non-arch distros use this
            certificatePath = Path.Join(
                "/usr/local/share/ca-certificates/",
                CA_FILE_NAME);
            File.WriteAllText(certificatePath, certificateText);
            Process.Start("update-ca-certificates").WaitForExit();
        }
        if (SystemIdentifier.GatheredInformation.OsPlatform ==
            OSPlatform.Windows)
        {
            // delete the CA if it exist (just in case)
            CommandExecutor.ExecuteCommand("certutil", $"-delstore \"Root\" \"{
                    CertificateGeneration.CA_COMMON_NAME}\"");

            certificatePath = Path.Join(Directory.CreateTempSubdirectory(
                    "dummyCA").FullName, CA_FILE_NAME);
            File.WriteAllText(certificatePath, certificateText);
            
            // add the newly stored CA as root
            CommandExecutor.ExecuteCommand("certutil", $"-addstore \"Root\" \"{
                certificatePath}\"");
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
                return File.Exists(
                    Path.Join(
                        "/etc/ca-certificates/trust-source/anchors/", 
                        CA_FILE_NAME));
            }
            return File.Exists(
                Path.Join(
                    "/usr/local/share/ca-certificates/", 
                    CA_FILE_NAME));
        }
        if (SystemIdentifier.GatheredInformation.OsPlatform ==
                 OSPlatform.Windows)
        {
            var output = CommandExecutor.ExecuteCommand("certutil",
                $"-verifystore \"Root\" \"{
                    CertificateGeneration.CA_COMMON_NAME}\"");
            return output.Contains(CertificateGeneration.CA_COMMON_NAME);
        }
        if (SystemIdentifier.GatheredInformation.OsPlatform ==
                 OSPlatform.OSX)
        {
            // todo:
        }

        // unreachable
        return true;
    }
}