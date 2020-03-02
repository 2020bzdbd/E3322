using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO.Ports;
using System.Threading;

namespace SerialPort_communication
{
    public partial class MainForm : Form
    {
        public MainForm()
        {
            InitializeComponent();
        }
        StringComparer stringComparer = StringComparer.OrdinalIgnoreCase;
        SerialPort serialPort = new SerialPort();
        List<String> MessageText = new List<String>();

        private void DataReceivedHandler(
                    object sender,
                    SerialDataReceivedEventArgs e)
        {
            SerialPort sp = (SerialPort)sender;
            string indata = sp.ReadExisting();
            showMessage(indata.TrimEnd((char[])"\n".ToCharArray()));
        }

        public void showMessage(string str)
        {
            MessageText.Add(str);
            if (MessageText.ToArray().Length > 15)
            {
                MessageText.RemoveAt(0);
            }
            String s = "";
            foreach (String mes in MessageText)
            {
                s += mes + "\n";
            }
            DisplayBar.Text = s;
        }

        private void btn_sent_Click(object sender, EventArgs e)
        {
            try
            {
                if (Message.Text != string.Empty)
                {

                    serialPort.WriteLine(UserName.Text + ": " + Message.Text + " [" + DateTime.Now.ToString()+"]");
                    showMessage(UserName.Text + ": " + Message.Text + " [" + DateTime.Now.ToString()+"]");
                    Message.Text = "";
                }
            }
            catch (Exception)
            {
                showMessage("串口尚未连接！");
            };
        }

        private void UserName_TextChanged(object sender, EventArgs e)
        {

        }

        private void SerialPortName_Leave(object sender, EventArgs e)
        {
            if (SerialPortName.Text == String.Empty)
                serialPort.PortName = "COM1";
            else serialPort.PortName = SerialPortName.Text;
            try
            {
                serialPort.Open();
            }
            catch (Exception) { }
        }

        private void SerialPortName_Enter(object sender, EventArgs e)
        {
            serialPort.Close();
            serialPort.DataReceived += new SerialDataReceivedEventHandler(DataReceivedHandler);
            serialPort.BaudRate = 9600;
            serialPort.Parity = Parity.None;
            serialPort.StopBits = StopBits.One;
            serialPort.DataBits = 8;
            serialPort.Handshake = Handshake.None;
            serialPort.RtsEnable = true;
            serialPort.ReadTimeout = 500;
            serialPort.WriteTimeout = 500;
        }
    }

}
