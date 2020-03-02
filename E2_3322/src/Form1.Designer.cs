namespace SerialPort_communication
{
    partial class MainForm
    {
        /// <summary>
        /// 必需的设计器变量。
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// 清理所有正在使用的资源。
        /// </summary>
        /// <param name="disposing">如果应释放托管资源，为 true；否则为 false。</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows 窗体设计器生成的代码

        /// <summary>
        /// 设计器支持所需的方法 - 不要修改
        /// 使用代码编辑器修改此方法的内容。
        /// </summary>
        private void InitializeComponent()
        {
            this.DisplayBar = new System.Windows.Forms.Label();
            this.UserName = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.SerialPortName = new System.Windows.Forms.TextBox();
            this.Message = new System.Windows.Forms.TextBox();
            this.btn_sent = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // DisplayBar
            // 
            this.DisplayBar.BorderStyle = System.Windows.Forms.BorderStyle.Fixed3D;
            this.DisplayBar.Font = new System.Drawing.Font("宋体", 12F);
            this.DisplayBar.Location = new System.Drawing.Point(173, 9);
            this.DisplayBar.Name = "DisplayBar";
            this.DisplayBar.Size = new System.Drawing.Size(488, 337);
            this.DisplayBar.TabIndex = 0;
            // 
            // UserName
            // 
            this.UserName.Font = new System.Drawing.Font("宋体", 12F);
            this.UserName.Location = new System.Drawing.Point(42, 78);
            this.UserName.Name = "UserName";
            this.UserName.Size = new System.Drawing.Size(100, 30);
            this.UserName.TabIndex = 1;
            this.UserName.TextChanged += new System.EventHandler(this.UserName_TextChanged);
            // 
            // label1
            // 
            this.label1.Font = new System.Drawing.Font("宋体", 12F);
            this.label1.Location = new System.Drawing.Point(42, 52);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(100, 23);
            this.label1.TabIndex = 2;
            this.label1.Text = "名称";
            this.label1.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // label2
            // 
            this.label2.Font = new System.Drawing.Font("宋体", 12F);
            this.label2.Location = new System.Drawing.Point(43, 143);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(100, 23);
            this.label2.TabIndex = 3;
            this.label2.Text = "串口";
            this.label2.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // SerialPortName
            // 
            this.SerialPortName.Font = new System.Drawing.Font("宋体", 12F);
            this.SerialPortName.Location = new System.Drawing.Point(42, 169);
            this.SerialPortName.Name = "SerialPortName";
            this.SerialPortName.Size = new System.Drawing.Size(100, 30);
            this.SerialPortName.TabIndex = 4;
            this.SerialPortName.Enter += new System.EventHandler(this.SerialPortName_Enter);
            this.SerialPortName.Leave += new System.EventHandler(this.SerialPortName_Leave);
            // 
            // Message
            // 
            this.Message.Font = new System.Drawing.Font("宋体", 12F);
            this.Message.Location = new System.Drawing.Point(173, 361);
            this.Message.Multiline = true;
            this.Message.Name = "Message";
            this.Message.Size = new System.Drawing.Size(406, 77);
            this.Message.TabIndex = 5;
            // 
            // btn_sent
            // 
            this.btn_sent.Font = new System.Drawing.Font("宋体", 12F);
            this.btn_sent.Location = new System.Drawing.Point(595, 361);
            this.btn_sent.Name = "btn_sent";
            this.btn_sent.Size = new System.Drawing.Size(66, 77);
            this.btn_sent.TabIndex = 6;
            this.btn_sent.Text = "发送";
            this.btn_sent.UseVisualStyleBackColor = true;
            this.btn_sent.Click += new System.EventHandler(this.btn_sent_Click);
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 15F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.btn_sent);
            this.Controls.Add(this.Message);
            this.Controls.Add(this.SerialPortName);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.UserName);
            this.Controls.Add(this.DisplayBar);
            this.Name = "MainForm";
            this.Text = "串口通信";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label DisplayBar;
        private System.Windows.Forms.TextBox UserName;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TextBox SerialPortName;
        private System.Windows.Forms.TextBox Message;
        private System.Windows.Forms.Button btn_sent;
    }
}

