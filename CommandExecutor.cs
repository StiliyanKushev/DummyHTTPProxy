using System;

namespace MyHttpProxy;

public abstract class CommandExecutor
{
    public static string ExecuteCommand(string command, string args, string? wd = null)
    {
        Console.WriteLine($"[EXECUTING COMMAND]: {command} {args}");
        var pProcess = new System.Diagnostics.Process();
        pProcess.StartInfo.FileName = command;
        pProcess.StartInfo.Arguments = args;
        pProcess.StartInfo.UseShellExecute = false;
        pProcess.StartInfo.RedirectStandardOutput = true;

        if (wd != null)
        {
            pProcess.StartInfo.WorkingDirectory = wd;
        }

        pProcess.Start();

        var output = pProcess.StandardOutput.ReadToEnd();
        pProcess.WaitForExit();
        return output;
    }
}