using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using SharpPcap;
using SharpPcap.Npcap;

namespace BandwidthMonitor
{
    public partial class MonitorForm : Form
    {
        public Boolean isRunning = false;
        private BackgroundWorker backgroundWorker = new BackgroundWorker
        {
            WorkerReportsProgress = true,
            WorkerSupportsCancellation = true
        };

        public MonitorForm()
        {
            InitializeComponent();
            backgroundWorker.DoWork += BackgroundWorkerOnDoWork;
            backgroundWorker.ProgressChanged += BackgroundWorkerOnProgressChanged;
        }

        private void BackgroundWorkerOnProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            
        }

        private void BackgroundWorkerOnDoWork(object sender, DoWorkEventArgs e)
        {
            Thread.Sleep(1000);
            BackgroundWorker worker = (BackgroundWorker)sender;
            while (!worker.CancellationPending)
            {
                GO();
                textBox1.Refresh();
                textBox2.Refresh();
                textBox3.Refresh();
                this.Refresh();
                Thread.Sleep(1000);
                worker.ReportProgress(0, "AN OBJECT TO PASS TO THE UI-THREAD");
            }
        }

        delegate void SetTextCallback(string text);

        private void SetText1(string text)
        {
            // InvokeRequired required compares the thread ID of the
            // calling thread to the thread ID of the creating thread.
            // If these threads are different, it returns true.
            if (this.textBox1.InvokeRequired)
            {
                SetTextCallback d = new SetTextCallback(SetText1);
                this.Invoke(d, new object[] { text });
            }
            else
            {
                this.textBox1.Text = text;
            }
        }

        private void SetText2(string text)
        {
            // InvokeRequired required compares the thread ID of the
            // calling thread to the thread ID of the creating thread.
            // If these threads are different, it returns true.
            if (this.textBox2.InvokeRequired)
            {
                SetTextCallback d = new SetTextCallback(SetText2);
                this.Invoke(d, new object[] { text });
            }
            else
            {
                this.textBox2.Text = text;
            }
        }

        private void SetText3(string text)
        {
            // InvokeRequired required compares the thread ID of the
            // calling thread to the thread ID of the creating thread.
            // If these threads are different, it returns true.
            if (this.textBox1.InvokeRequired)
            {
                SetTextCallback d = new SetTextCallback(SetText3);
                this.Invoke(d, new object[] { text });
            }
            else
            {
                this.textBox3.Text = text;
            }
        }

        private void GO_Click(object sender, EventArgs e)
        {
            backgroundWorker.RunWorkerAsync();
        }

        public class ProcessPerformanceInfo
        {
            public int ProcessID { get; set; }
            public long NetSendBytes { get; set; }
            public long NetRecvBytes { get; set; }
            public long NetTotalBytes { get; set; }

        }
        static ProcessPerformanceInfo ProcInfo;
        private void GO()
        {
            ProcInfo = new ProcessPerformanceInfo()
            {
                ProcessID = 3684
            };
        
            int pid = ProcInfo.ProcessID;
            List<int> ports = new List<int>();
        
            #region get ports for certain process through executing the netstat -ano command  in cmd
            Process pro = new Process();
            pro.StartInfo.FileName = "cmd.exe";
            pro.StartInfo.UseShellExecute = false;
            pro.StartInfo.RedirectStandardInput = true;
            pro.StartInfo.RedirectStandardOutput = true;
            pro.StartInfo.RedirectStandardError = true;
            pro.StartInfo.CreateNoWindow = true;
            pro.Start();
            pro.StandardInput.WriteLine("netstat -ano");
            pro.StandardInput.WriteLine("exit");
            Regex reg = new Regex("\\s+", RegexOptions.Compiled);
            string line = null;
            ports.Clear();
            while ((line = pro.StandardOutput.ReadLine()) != null)
            {
                line = line.Trim();
                if (line.StartsWith("TCP", StringComparison.OrdinalIgnoreCase))
                {
                    line = reg.Replace(line, ",");
                    string[] arr = line.Split(',');
                    if (arr[4] == pid.ToString())
                    {
                        string soc = arr[1];
                        int pos = soc.LastIndexOf(':');
                        int pot = int.Parse(soc.Substring(pos + 1));
                        ports.Add(pot);
                    }
                }
                else if (line.StartsWith("UDP", StringComparison.OrdinalIgnoreCase))
                {
                    line = reg.Replace(line, ",");
                    string[] arr = line.Split(',');
                    if (arr[3] == pid.ToString())
                    {
                        string soc = arr[1];
                        int pos = soc.LastIndexOf(':');
                        int pot = int.Parse(soc.Substring(pos + 1));
                        ports.Add(pot);
                    }
                }
            }
            pro.Close();
            #endregion
        
            //get ip address
            IPAddress[] addrList = Dns.GetHostByName(Dns.GetHostName()).AddressList;
            string IP = addrList[0].ToString();
        
        
            //var devices = NpcapDeviceList.Instance;
            var devices = CaptureDeviceList.Instance;
        
            // differentiate based upon types
        
            int count = devices.Count;
            if (count < 1)
            {
                Console.WriteLine("No device found on this machine");
                return;
            }
        
            for (int i = 0; i < count; ++i)
            {
                for (int j = 0; j < ports.Count; ++j)
                {
                    CaptureFlowRecv(IP, ports[j], i);
                    CaptureFlowSend(IP, ports[j], i);
                }
            }
            while (true)
            {
                SetText1("proc NetTotalBytes : " + ProcInfo.NetTotalBytes);
                SetText2("proc NetSendBytes : " + ProcInfo.NetSendBytes);
                SetText3("proc NetRecvBytes : " + ProcInfo.NetRecvBytes);

                //Call refresh function every 1s 
                RefreshInfo();
            }
        
        }
        
        private static void CaptureFlowSend(string IP, int portID, int deviceID)
        {
            ICaptureDevice device = CaptureDeviceList.New()[deviceID];
        
            device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrivalSend);
            int readTimeoutMilliseconds = 1000;
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);
            string filter = "src host " + IP + " and src port " + portID;
            device.Filter = filter;
            device.StartCapture();
        
        }
        
        private static void device_OnPacketArrivalSend(object sender, CaptureEventArgs e)
        {
            //DateTime time = e.Packet.Timeval.Date;
            //int len = e.Packet.Data.Length;
            //Console.WriteLine("{0}:{1}:{2},{3} Len={4}",
            //    time.Hour, time.Minute, time.Second, time.Millisecond, len);
            var len = e.Packet.Data.Length;
            ProcInfo.NetSendBytes += len;
        
        }
        
        private static void CaptureFlowRecv(string IP, int portID, int deviceID)
        {
            ICaptureDevice device = CaptureDeviceList.New()[deviceID];
            device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrivalRecv);
        
            int readTimeoutMilliseconds = 1000;
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);
        
            string filter = "dst host " + IP + " and dst port " + portID;
            device.Filter = filter;
            device.StartCapture();
        
        }
        private static void device_OnPacketArrivalRecv(object sender, CaptureEventArgs e)
        {
            var len = e.Packet.Data.Length;
            ProcInfo.NetRecvBytes += len;
        }
        public static void RefreshInfo()
        {
            ProcInfo.NetRecvBytes = 0;
            ProcInfo.NetSendBytes = 0;
            ProcInfo.NetTotalBytes = 0;
            Thread.Sleep(1000);
            ProcInfo.NetTotalBytes = ProcInfo.NetRecvBytes + ProcInfo.NetSendBytes;
        }

        private static void Device_OnPacketArrivalRecv(object sender, CaptureEventArgs e)
        {
            var len = e.Packet.Data.Length;
            ProcInfo.NetRecvBytes += len;
        }
    }
}
