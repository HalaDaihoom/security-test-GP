using System.Diagnostics;

namespace Api.Services
{
    public class SubzyTestService
    {
        private readonly string _toolsPath = "/app/tools"; // Make sure tools are mounted or copied here

        public async Task<string> TestScanAsync(string domain)
        {
            string subsFile = Path.Combine(_toolsPath, $"subs_{domain}.txt");
            string resultFile = Path.Combine(_toolsPath, $"result_{domain}.txt");

            try
            {
                await RunCommandAsync($"assetfinder {domain} > \"{subsFile}\"");
                await RunCommandAsync($"subzy run --targets \"{subsFile}\" > \"{resultFile}\"");

                // 🔹 Read the result
                string result = await File.ReadAllTextAsync(resultFile);
                return result;
            }
            finally
            {
                // 🔸 Optional cleanup
                if (File.Exists(subsFile)) File.Delete(subsFile);
                if (File.Exists(resultFile)) File.Delete(resultFile);
            }
        }

        private Task RunCommandAsync(string command)
        {
            var tcs = new TaskCompletionSource();

            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "bash",
                    Arguments = $"-c \"{command}\"",
                    //WorkingDirectory = _toolsPath,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                },
                EnableRaisingEvents = true
            };

            // Optional: log output to console
            process.OutputDataReceived += (sender, args) =>
            {
                if (!string.IsNullOrEmpty(args.Data))
                    Console.WriteLine("[stdout] " + args.Data);
            };

            process.ErrorDataReceived += (sender, args) =>
            {
                if (!string.IsNullOrEmpty(args.Data))
                    Console.Error.WriteLine("[stderr] " + args.Data);
            };

            process.Exited += (sender, args) =>
            {
                tcs.SetResult();
                process.Dispose();
            };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            return tcs.Task;
        }
    }
}


// using System.Diagnostics;

// namespace Api.Services
// {
//     public class SubzyTestService
//     {
//         private readonly string _toolsPath = @"C:\Tools";

//         public async Task<string> TestScanAsync(string domain)
//         {
//             string subsFile = Path.Combine(_toolsPath, $"subs_{domain}.txt");
//             string resultFile = Path.Combine(_toolsPath, $"result_{domain}.txt");

//             try
//             {
//                 //  run assetfinder
//                 await RunCommandAsync($"assetfinder.exe {domain} > \"{subsFile}\"");

//                 //  run subzy
//                 await RunCommandAsync($"subzy.exe run --targets \"{subsFile}\" > \"{resultFile}\"");

//                 // read result
//                 string result = await File.ReadAllTextAsync(resultFile);

//                 return result;
//             }
//             finally
//             {
//                 // Optional cleanup
//                 if (File.Exists(subsFile)) File.Delete(subsFile);
//                 if (File.Exists(resultFile)) File.Delete(resultFile);
//             }
//         }

//         private Task RunCommandAsync(string command)
//         {
//             var tcs = new TaskCompletionSource();
//             var process = new Process
//             {
//                 StartInfo = new ProcessStartInfo("cmd.exe", $"/C {command}")
//                 {
//                     WorkingDirectory = _toolsPath,
//                     UseShellExecute = false,
//                     CreateNoWindow = true
//                 },
//                 EnableRaisingEvents = true
//             };

//             process.Exited += (sender, args) =>
//             {
//                 tcs.SetResult();
//                 process.Dispose();
//             };

//             process.Start();
//             return tcs.Task;
//         }
//     }
// }
