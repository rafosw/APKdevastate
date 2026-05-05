using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace APKdevastate
{
    public partial class aboutform : Form
    {
        public aboutform()
        {
            InitializeComponent();
        }

        private void pictureBox3_Click(object sender, EventArgs e)
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "https://www.instagram.com/rafok2v9c/",
                UseShellExecute = true
            };
            Process.Start(psi);
        }

        private void pictureBox2_Click(object sender, EventArgs e)
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "https://github.com/rafosw",
                UseShellExecute = true
            };
            Process.Start(psi);
        }

        private void pictureBox4_Click(object sender, EventArgs e)
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "https://rafosw.github.io",
                UseShellExecute = true
            };
            Process.Start(psi);
        }

        private void label3_Click(object sender, EventArgs e)
        {

        }
    }
}
