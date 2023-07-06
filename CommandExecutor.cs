namespace MyHttpProxy;

public abstract class CommandExecutor
{
    public static string ExecuteCommand(string command, string args, string? wd = null)
    {
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