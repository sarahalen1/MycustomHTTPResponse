using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using EncryptionDecryptionUsingSymmetricKey;
using Microsoft.Identity.Client;
using nfapinet;
using NT8GhosTmo.Properties;
using pfapinet;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using System.Xml.Linq;
using static System.Net.Mime.MediaTypeNames;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.Button;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.StartPanel;



namespace PFNetFilterCS
{
    

    public partial class Form1 : Form
    {
       

        public Form1()
        {
            InitializeComponent();

          
            
        }


        Filter m_filter = new Filter();
        PFObject m_storageObject = PFObject.create(PF_ObjectType.OT_NULL, 1);

        private void Start_Click(object sender, EventArgs e)
        {
            // SSL parameters
            m_filter.setParam(ContentFilterParam.CFP_FILTER_SSL, ssl.Checked); // SSL
            m_filter.setParam(ContentFilterParam.CFP_FILTER_RAW, raw.Checked); // Raw

            // HTTP parameters
            m_filter.setParam(ContentFilterParam.CFP_URL_STOP_NT8, urlstopword); // Url Stopword





            if (m_filter.start(this))
            {
                Start.Enabled = false;
                Stop.Enabled = true;
            }
        }

        private void Stop_Click(object sender, EventArgs e)
        {
            m_filter.stop();
            Start.Enabled = true;
            Stop.Enabled = false;


        }

        private void AnitDebuggers_CheckedChanged(object sender, EventArgs e)
        {

            m_filter.setParam(ContentFilterParam.CFP_FILTER_SSL, ssl.Checked); // ssl


        }
        private void Test_CheckedChanged(object sender, EventArgs e)
        {
            m_filter.setParam(ContentFilterParam.CFP_FILTER_RAW, raw.Checked); // raw


        }
       


        private void CustomRsp_TextChanged(object sender, EventArgs e) // URL Stop word
        {
            m_filter.setParam(ContentFilterParam.CFP_URL_STOP_NT8, urlstopword);

        }
      

        //********** Url Keywords to Block when API is hit 
        static string urlstopword = "checkv2"; 
      
        //**********














        public unsafe class NFUtil
        {
            public static SocketAddress convertAddress(byte[] buf)
            {
                if (buf == null)
                {
                    return new SocketAddress(AddressFamily.InterNetwork);
                }

                SocketAddress addr = new SocketAddress((AddressFamily)(buf[0]), (int)NF_CONSTS.NF_MAX_ADDRESS_LENGTH);

                for (int i = 0; i < (int)NF_CONSTS.NF_MAX_ADDRESS_LENGTH; i++)
                {
                    addr[i] = buf[i];
                }

                return addr;
            }

            public static string addressToString(SocketAddress addr)
            {
                IPEndPoint ipep;

                if (addr.Family == AddressFamily.InterNetworkV6)
                {
                    ipep = new IPEndPoint(IPAddress.IPv6None, 0);
                }
                else
                {
                    ipep = new IPEndPoint(0, 0);
                }
                ipep = (IPEndPoint)ipep.Create(addr);
                return ipep.ToString();
            }
        }

        string getSessionProperties(NF_TCP_CONN_INFO connInfo)
        {
            string s = "";

            try
            {
                SocketAddress localAddr = NFUtil.convertAddress(connInfo.localAddress);
                s += NFUtil.addressToString(localAddr);

                s += "<->";

                SocketAddress remoteAddr = NFUtil.convertAddress(connInfo.remoteAddress);
                s += NFUtil.addressToString(remoteAddr);
            }
            catch (Exception)
            {
            }

            s += " [pid=" + connInfo.processId + " owner=" + PFAPI.pf_getProcessOwnerW(connInfo.processId) + "] ";

            s += NFAPI.nf_getProcessName(connInfo.processId);

            return s;
        }


        void updateSessionListInternal(ulong id, NF_TCP_CONN_INFO pConnInfo, bool newItem)
        {
            if (newItem)
            {
                string sid = Convert.ToString(id);
              //  ListViewItem lvi = Sessions.Items.Add(sid, sid, -1);
                //lvi.SubItems.Add(getSessionProperties(pConnInfo));
            }
            else
            {
               // Sessions.Items.RemoveByKey(Convert.ToString(id));
            }
        }

        delegate void dgUpdateSessionList(ulong id, NF_TCP_CONN_INFO pConnInfo, bool newItem);

        public void updateSessionListSafe(ulong id, NF_TCP_CONN_INFO pConnInfo, bool newItem)
        {
            BeginInvoke(new dgUpdateSessionList(updateSessionListInternal),
                new Object[] { id, pConnInfo, newItem });
        }

        unsafe ulong saveObject(PFObject obj)
        {
            int ot, nStreams;
            uint streamLen, rwLen;
            ulong pos = 0;
            PFStream pStg = m_storageObject.getStream(0);
            byte[] tempBuf = new byte[1000];

            fixed (byte* pTempBuf = tempBuf)
            {
                pos = pStg.seek(0, (int)SeekOrigin.End);

                ot = (int)obj.getType();
                pStg.write((IntPtr)(byte*)&ot, (uint)sizeof(int));
                nStreams = (int)obj.getStreamCount();
                pStg.write((IntPtr)(byte*)&nStreams, (uint)sizeof(int));
                for (int i = 0; i < nStreams; i++)
                {
                    PFStream pStream = obj.getStream(i);
                    pStream.seek(0, (int)SeekOrigin.Begin);
                    streamLen = (uint)pStream.size();
                    pStg.write((IntPtr)(byte*)&streamLen, (uint)sizeof(uint));
                    while (streamLen > 0)
                    {
                        rwLen = (uint)Math.Min(tempBuf.Length, streamLen);
                        rwLen = pStream.read((IntPtr)pTempBuf, rwLen);
                        if (rwLen <= 0)
                            break;
                        pStg.write((IntPtr)pTempBuf, rwLen);
                        streamLen -= rwLen;
                    }
                    pStream.seek(0, (int)SeekOrigin.Begin);
                }
            }

            return pos;
        }

        unsafe PFObject loadObject(ulong offset)
        {
            int ot, nStreams;
            uint streamLen, rwLen;
            PFStream pStg = m_storageObject.getStream(0);
            byte[] tempBuf = new byte[1000];
            PFObject obj = null;

            fixed (byte* pTempBuf = tempBuf)
            {
                pStg.seek(offset, (int)SeekOrigin.Begin);

                pStg.read((IntPtr)(byte*)&ot, (uint)sizeof(int));
                pStg.read((IntPtr)(byte*)&nStreams, (uint)sizeof(int));

                obj = PFObject.create((PF_ObjectType)ot, nStreams);

                for (int i = 0; i < nStreams; i++)
                {
                    PFStream pStream = obj.getStream(i);
                    pStg.read((IntPtr)(byte*)&streamLen, (uint)sizeof(uint));
                    while (streamLen > 0)
                    {
                        rwLen = (uint)Math.Min(tempBuf.Length, streamLen);
                        rwLen = pStg.read((IntPtr)pTempBuf, rwLen);
                        if (rwLen <= 0)
                            break;
                        pStream.write((IntPtr)pTempBuf, rwLen);
                        streamLen -= rwLen;
                    }
                    pStream.seek(0, (int)SeekOrigin.Begin);
                }
            }

            return obj;
        }

        private int c = 0;
       


        void addObjectInternal(ulong id, PFObject obj, bool blocked)
        {
            string sid = Convert.ToString(id);

            switch (obj.getType())
            {
                case PF_ObjectType.OT_HTTP_REQUEST:
                case PF_ObjectType.OT_HTTP_RESPONSE:
                case PF_ObjectType.OT_HTTP2_REQUEST:
                case PF_ObjectType.OT_HTTP2_RESPONSE:
                 
                    break;
              
              
             
                case PF_ObjectType.OT_RAW_OUTGOING:
                case PF_ObjectType.OT_RAW_INCOMING:
               
                    break;
              
                
            }

           
        }

        delegate void dgAddObject(ulong id, PFObject obj, bool blocked);

        public void addObjectSafe(ulong id, PFObject obj, bool blocked)
        {
            BeginInvoke(new dgAddObject(addObjectInternal),
                new Object[] { id, obj, blocked });
        }


        private void Form1_FormClosed(object sender, FormClosedEventArgs e)
        {
            m_filter.stop();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            Environment.Exit(0);
        }
        private void button3_Click(object sender, EventArgs e)
        {
            WindowState = FormWindowState.Minimized;
        }


        //****** Mouse Hove Function
        public Point mouseLocation;
        private void mouse_Down(object sender, MouseEventArgs e)
        {
            mouseLocation = new Point(-e.X, -e.Y);
        }

        private void mouse_Move(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left)
            {
                Point mousePose = Control.MousePosition;
                mousePose.Offset(mouseLocation.X, mouseLocation.Y);
                Location = mousePose;
            }
        }

    }
}