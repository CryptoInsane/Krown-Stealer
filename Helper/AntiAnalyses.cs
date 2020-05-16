using System;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;


namespace who.Helper
{
    class AntiAnalyses
    {
        public static string[] Processes = new string[]
            {
                "HttpAnalyzer", "Dumper", "Reflector", "Wireshark", "WPE",
                "ProcessExplorer", "IDA", "HTTP Debugger Pro", "The Wireshark Network Analyzer", "WinDbg", "Colasoft Capsa",
                "smsniff", "Olly", "OllyDbg", "WPE PRO", "Microsoft Network Monitor", "Fiddler",
                "SmartSniff", "Immunity Debugger" , "Process Explorer" , "PE Tools","AQtime", "DS-5 Debug", "Dbxtool",
                "Topaz", "FusionDebug", "NetBeans", "Rational Purify", ".NET Reflector", "Cheat Engine", "Sigma Engine"
            };


        public static void Proc()
        {
            foreach (string ProcName in Processes)
            {
                if (Process.GetProcesses().Any(x => x.ProcessName.ToLower().Contains(ProcName)))
                {
                    Environment.Exit(0);
                }
            }                              
        }
        
        public static void VMDetect() // VM
        {
            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("Select * from Win32_ComputerSystem"))
            {
                using (ManagementObjectCollection items = searcher.Get())
                {
                    foreach (ManagementBaseObject item in items)
                    {
                        string manufacturer = item["Manufacturer"].ToString().ToLower();
                        if ((manufacturer == "microsoft corporation" && item["Model"].ToString().ToUpperInvariant().Contains("VIRTUAL"))
                            || manufacturer.Contains("vmware")
                            || item["Model"].ToString() == "VirtualBox")
                        {
                            Environment.Exit(0);
                        }
                    }
                }
            }
        }

        public static void SandboxieDetect()
        {
            if (GetModuleHandle("SbieDll.dll").ToInt32() != 0)
            {
                Environment.Exit(0);
            }
        }

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);
    }
}
