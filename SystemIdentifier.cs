using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace MyHttpProxy;

public struct SystemInformation
{
    public OSPlatform OsPlatform;
    public enum OSFlavor
    {
        DEBIAN,
        UBUNTU,
        ARCH
    }
    public OSFlavor OsFlavor;
}

public abstract class SystemIdentifier
{
    /// <summary>
    /// Should be used at runtime to get any data about the system.
    /// </summary>
    public static SystemInformation GatheredInformation;
    
    /// <summary>
    /// Called only once initially at startup to gather data about the system.
    /// </summary>
    public static void GatherInformation()
    {
        GatheredInformation = new SystemInformation();

        // define the os platform we're using
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            GatheredInformation.OsPlatform = OSPlatform.Windows;
        } 
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            GatheredInformation.OsPlatform = OSPlatform.Linux;
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            GatheredInformation.OsPlatform = OSPlatform.OSX;
        }

        if (GatheredInformation.OsPlatform == OSPlatform.Linux)
        {
            // define the flavor (linux only)
            var distroId = GetLinuxDistroId();

            if (distroId == null)
            {
                Console.WriteLine("Fatal: unrecognized linux distro.");
                Environment.Exit(1);
            }
            else if(distroId.Contains("debian"))
            {
                GatheredInformation.OsFlavor = SystemInformation.OSFlavor.DEBIAN;
            }
            else if(distroId.Contains("ubuntu"))
            {
                GatheredInformation.OsFlavor = SystemInformation.OSFlavor.UBUNTU;
            }
            else if(distroId.Contains("arch"))
            {
                GatheredInformation.OsFlavor = SystemInformation.OSFlavor.ARCH;
            }
        }
    }
    
    [SupportedOSPlatform("linux")]
    private static string? GetLinuxDistroId()
    {
        // Read the ID from the "/etc/os-release" file
        var osReleasePath = "/etc/os-release";
        string? distroId = null;

        if (!File.Exists(osReleasePath)) return distroId;
        var lines = File.ReadAllLines(osReleasePath);

        foreach (var line in lines)
        {
            if (!line.StartsWith("ID=")) continue;
            distroId = line[3..].Trim('"');
            break;
        }

        return distroId!.ToLower();
    }
}