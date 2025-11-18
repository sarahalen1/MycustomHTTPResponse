using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using EncryptionDecryptionUsingSymmetricKey;
using nfapinet;
using pfapinet;
using System;
using System.Collections;
using System.Collections.Specialized;
using System.ComponentModel.Composition.Primitives;
using System.Diagnostics.Metrics;
using System.Dynamic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Policy;
using System.ServiceModel.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using System.Xml.Linq;
using static System.Windows.Forms.VisualStyles.VisualStyleElement;




namespace PFNetFilterCS
{



    enum ContentFilterParam
    {
        CFP_FILTER_SSL, //ssl
        CFP_FILTER_RAW, // raw
        CFP_URL_STOP_NT8, // URL stop word

    };



    class Filter : PFEventsDefault
    {
        private Form1 m_form = null;
        private Hashtable m_params = new Hashtable();

        



        // Custom HTTP Response Content body
        static string CustomRsp = "If you See **12345** Then its means Custom Response is Working";







        public override void tcpConnected(ulong id, NF_TCP_CONN_INFO pConnInfo)
        {
            if (pConnInfo.direction == (byte)NF_DIRECTION.NF_D_OUT)
            {
                bool filterSSL;

                PFAPI.pf_addFilter(id,
                    PF_FilterType.FT_PROXY,
                    PF_FilterFlags.FF_DEFAULT,
                    PF_OpTarget.OT_LAST,
                    PF_FilterType.FT_NONE);

                lock (m_params)
                {
                    filterSSL = (bool)m_params[ContentFilterParam.CFP_FILTER_SSL];
                    if (filterSSL)
                    {
                        PFAPI.pf_addFilter(id,
                            PF_FilterType.FT_SSL,
                            PF_FilterFlags.FF_SSL_VERIFY | PF_FilterFlags.FF_SSL_TLS_AUTO,
                            PF_OpTarget.OT_LAST,
                            PF_FilterType.FT_NONE);
                    }
                }

                PFAPI.pf_addFilter(id,
                    PF_FilterType.FT_HTTP,
                    PF_FilterFlags.FF_HTTP_FILTER_WEBSOCKET,
                    PF_OpTarget.OT_LAST,
                    PF_FilterType.FT_NONE);

                PFAPI.pf_addFilter(id,
                    PF_FilterType.FT_HTTP2,
                    PF_FilterFlags.FF_DEFAULT,
                    PF_OpTarget.OT_LAST,
                    PF_FilterType.FT_NONE);

                PFAPI.pf_addFilter(id,
                    PF_FilterType.FT_SMTP,
                    filterSSL ? PF_FilterFlags.FF_SSL_TLS : PF_FilterFlags.FF_DEFAULT,
                    PF_OpTarget.OT_LAST,
                    PF_FilterType.FT_NONE);

                PFAPI.pf_addFilter(id,
                    PF_FilterType.FT_POP3,
                    filterSSL ? PF_FilterFlags.FF_SSL_TLS : PF_FilterFlags.FF_DEFAULT,
                    PF_OpTarget.OT_LAST,
                    PF_FilterType.FT_NONE);

                PFAPI.pf_addFilter(id,
                    PF_FilterType.FT_NNTP,
                    filterSSL ? PF_FilterFlags.FF_SSL_TLS : PF_FilterFlags.FF_DEFAULT,
                    PF_OpTarget.OT_LAST,
                    PF_FilterType.FT_NONE);

                PFAPI.pf_addFilter(id,
                    PF_FilterType.FT_FTP,
                    (filterSSL ? PF_FilterFlags.FF_SSL_TLS : PF_FilterFlags.FF_DEFAULT) |
                        PF_FilterFlags.FF_READ_ONLY_IN | PF_FilterFlags.FF_READ_ONLY_OUT,
                    PF_OpTarget.OT_LAST,
                    PF_FilterType.FT_NONE);

                PFAPI.pf_addFilter(id,
                    PF_FilterType.FT_ICQ,
                    0,//PF_FilterFlags.FF_READ_ONLY_IN | PF_FilterFlags.FF_READ_ONLY_OUT,
                    PF_OpTarget.OT_LAST,
                    PF_FilterType.FT_NONE);

                PFAPI.pf_addFilter(id,
                    PF_FilterType.FT_XMPP,
                    (filterSSL ? PF_FilterFlags.FF_SSL_TLS : PF_FilterFlags.FF_DEFAULT) |
                        PF_FilterFlags.FF_READ_ONLY_IN | PF_FilterFlags.FF_READ_ONLY_OUT,
                    PF_OpTarget.OT_LAST,
                    PF_FilterType.FT_NONE);

                lock (m_params)
                {
                    if ((bool)m_params[ContentFilterParam.CFP_FILTER_RAW])
                    {
                        PFAPI.pf_addFilter(id,
                            PF_FilterType.FT_RAW,
                            PF_FilterFlags.FF_DEFAULT,
                            PF_OpTarget.OT_LAST,
                            PF_FilterType.FT_NONE);
                    }
                }
            }

            m_form.updateSessionListSafe(id, pConnInfo, true);
        }

        public override void tcpClosed(ulong id, NF_TCP_CONN_INFO pConnInfo)
        {
            m_form.updateSessionListSafe(id, pConnInfo, false);
        }

        public unsafe string loadString(PFStream pStream, bool seekToBegin)
        {
            if (pStream == null || pStream.size() == 0)
                return "";

            byte[] buf = new byte[pStream.size() + 1];
            uint len = 0;

            if (seekToBegin)
            {
                pStream.seek(0, (int)SeekOrigin.Begin);
            }

            fixed (byte* p = buf)
            {
                len = pStream.read((IntPtr)p, (uint)pStream.size());

                char[] cbuf = new char[len];

                for (int i = 0; i < len; i++)
                {
                    cbuf[i] = (char)buf[i];
                }

                return new String(cbuf);
            }
        }

        public unsafe string loadUnicodeString(PFStream pStream, bool seekToBegin)
        {
            if (pStream == null || pStream.size() == 0)
                return "";

            byte[] buf = new byte[pStream.size() + 2];
            uint len = 0;

            if (seekToBegin)
            {
                pStream.seek(0, (int)SeekOrigin.Begin);
            }

            fixed (byte* p = buf)
            {
                len = pStream.read((IntPtr)p, (uint)pStream.size());
                buf[len] = 0;
                buf[len + 1] = 0;

                char[] cbuf = new char[len + 1];

                for (int i = 0; i < len; i += 2)
                {
                    cbuf[i / 2] = (char)(buf[i] + 256 * buf[i + 1]);
                }

                return new String(cbuf);
            }
        }

        public unsafe string loadUTF8String(PFStream pStream, bool seekToBegin)
        {
            if (pStream == null || pStream.size() == 0)
                return "";

            byte[] buf = new byte[pStream.size() + 1];
            uint len = 0;

            if (seekToBegin)
            {
                pStream.seek(0, (int)SeekOrigin.Begin);
            }

            fixed (byte* p = buf)
            {
                len = pStream.read((IntPtr)p, (uint)pStream.size());
                buf[len] = 0;

                Encoding e = new UTF8Encoding();
                string s = e.GetString(buf);
                return s;
            }
        }

        public unsafe int loadInt(PFStream pStream, bool seekToBegin)
        {
            if (pStream == null || pStream.size() == 0)
                return 0;

            Int32 res = 0;

            if (seekToBegin)
            {
                pStream.seek(0, (int)SeekOrigin.Begin);
            }

            pStream.read((IntPtr)(byte*)&res, (uint)sizeof(Int32));

            return res;
        }


        unsafe bool saveString(PFStream pStream, string s, bool clearStream)
        {
            if (pStream == null)
                return false;

            if (clearStream)
            {
                pStream.reset();
            }

            foreach (char c in s.ToCharArray())
            {
                byte b = (byte)c;
                if (pStream.write((IntPtr)(byte*)&b, (uint)1) < 1)
                    return false;
            }
            return true;
        }

        public string getHttpUrl(PFObject pObject)
        {
            string url = "", status, host, uri;

            if (pObject.getType() == PF_ObjectType.OT_HTTP_REQUEST ||
                pObject.getType() == PF_ObjectType.OT_HTTP_RESPONSE)
            {
                try
                {

                    PFHeader h = PFAPI.pf_readHeader(pObject.getStream((int)PF_HttpStream.HS_HEADER));

                    if (pObject.getType() == PF_ObjectType.OT_HTTP_REQUEST)
                    {
                        host = h["Host"];
                        status = loadString(pObject.getStream((int)PF_HttpStream.HS_STATUS), true);
                    }
                    else
                    {
                        host = h[CustomHTTPHeaders.HTTP_EXHDR_RESPONSE_HOST];
                        status = h[CustomHTTPHeaders.HTTP_EXHDR_RESPONSE_REQUEST];
                    }

                    int pos = status.IndexOf(' ');
                    if (pos != -1)
                    {
                        pos++;

                        int pEnd = status.IndexOf(' ', pos);

                        if (pEnd != -1)
                        {
                            uri = status.Substring(pos, pEnd - pos);
                            if (uri.StartsWith("http://"))
                            {
                                url = uri;
                            }
                            else
                            {
                                url = "http://" + host + uri;
                            }
                        }
                    }
                }
                catch (Exception)
                {
                    url = "";
                }
            }
            else
            if (pObject.getType() == PF_ObjectType.OT_HTTP2_REQUEST ||
                pObject.getType() == PF_ObjectType.OT_HTTP2_RESPONSE)
            {
                try
                {

                    PFHeader h = PFAPI.pf_readHeader(pObject.getStream((int)PF_Http2Stream.H2S_HEADER));

                    if (pObject.getType() == PF_ObjectType.OT_HTTP2_REQUEST)
                    {
                        host = h[":authority"];
                        uri = h[":path"];
                    }
                    else
                    {
                        host = h[CustomHTTP2Headers.HTTP2_EXHDR_AUTHORITY];
                        uri = h[CustomHTTP2Headers.HTTP2_EXHDR_PATH];
                    }

                    url = "http://" + host + uri;
                }
                catch (Exception)
                {
                    url = "";
                }
            }

            return url;
        }


        //******  Custom Response For CFP_URL_STOP_NT8
        void postBlockHttpResponse(ulong id)

        {
            PFObject obj = PFObject.create(PF_ObjectType.OT_HTTP_RESPONSE, 3);

            saveString(obj.getStream((int)PF_HttpStream.HS_STATUS), "HTTP/1.1 200 OK\r\n", true);

            PFHeader h = new PFHeader();
            h.Add("Content-Type", "text/html");
            h.Add("Content-Length", Convert.ToString(CustomRsp.Length));
            h.Add("Connection", "close");


            PFAPI.pf_writeHeader(obj.getStream((int)PF_HttpStream.HS_HEADER), h);

            saveString(obj.getStream((int)PF_HttpStream.HS_CONTENT), CustomRsp, true); 

            PFAPI.pf_postObject(id, ref obj);

            obj.free();
        }



        bool filterHTTPRequest(ulong id, PFObject pObject)
        {
            bool block = false;
            string urlStopWord;


            lock (m_params)
            {
                urlStopWord = (string)m_params[ContentFilterParam.CFP_URL_STOP_NT8];

            }

            string url = getHttpUrl(pObject).ToLower();


            if (urlStopWord != null && urlStopWord.Length > 0)
            {
                urlStopWord = urlStopWord.ToLower();

                if (url.Contains(urlStopWord))
                {

                    postBlockHttpResponse(id); // If urlstopword "checkv2" is hit, modify with custom response


                    block = true;

                }
            }

                return block;
            }
        
    

        public override void dataAvailable(ulong id, ref PFObject pObject)

        {
            bool blocked = false;
            PFObject clone = pObject.detach();

            clone.setReadOnly(pObject.isReadOnly());

            if (!pObject.isReadOnly())
            {
                try
                {
                    switch (pObject.getType())
                    {

                        case PF_ObjectType.OT_HTTP_REQUEST:
                        case PF_ObjectType.OT_HTTP2_REQUEST:
                            blocked = filterHTTPRequest(id, clone);
                            break;

                    }
                }
                catch (Exception)
                {
                }
            }

            if (!blocked)
                PFAPI.pf_postObject(id, ref clone);

            m_form.addObjectSafe(id, clone, blocked);
        }
        public override PF_DATA_PART_CHECK_RESULT dataPartAvailable(ulong id, ref PFObject pObject)



        {
            try
            {
                if (pObject.getType() == PF_ObjectType.OT_SSL_INVALID_SERVER_CERTIFICATE)
                {
                    return PF_DATA_PART_CHECK_RESULT.DPCR_FILTER;
                }

                if (pObject.getType() == PF_ObjectType.OT_HTTP_RESPONSE ||
                    pObject.getType() == PF_ObjectType.OT_HTTP2_RESPONSE)
                {
                    if (pObject.getStream((int)PF_HttpStream.HS_CONTENT).size() < 5)
                        return PF_DATA_PART_CHECK_RESULT.DPCR_MORE_DATA_REQUIRED;

                    PFHeader h = PFAPI.pf_readHeader(pObject.getStream((int)PF_HttpStream.HS_HEADER));

                    string contentType = h["Content-Type"];
                    if (contentType == null)
                        return PF_DATA_PART_CHECK_RESULT.DPCR_FILTER_READ_ONLY;


                }
                else
                    if (pObject.getType() == PF_ObjectType.OT_HTTP_REQUEST ||
                        pObject.getType() == PF_ObjectType.OT_HTTP2_REQUEST)
                {
                    if (filterHTTPRequest(id, pObject))
                    {
                        // Request blocked
                        return PF_DATA_PART_CHECK_RESULT.DPCR_BLOCK;
                    }
                }
            }
            catch (Exception)
            {
            }

            return PF_DATA_PART_CHECK_RESULT.DPCR_FILTER_READ_ONLY;
        }
        public void setParam(ContentFilterParam type, object value)
        {
            lock (m_params)
            {
                m_params[type] = value;
            }
        }
        public bool start(Form1 form)
        {
            m_form = form;

            if (!PFAPI.pf_init(this, "c:\\netfilter2"))
                return false;

            //            PFAPI.pf_setExceptionsTimeout(eEXCEPTION_CLASS.EXC_GENERIC, 60 * 60);
            //            PFAPI.pf_setExceptionsTimeout(eEXCEPTION_CLASS.EXC_TLS, 60 * 60);
            //            PFAPI.pf_setExceptionsTimeout(eEXCEPTION_CLASS.EXC_CERT_REVOKED, 60 * 60);

            PFAPI.pf_setRootSSLCertSubject("NFSDK Sample CA");


            if (NFAPI.nf_init("netfilter2", PFAPI.pf_getNFEventHandler()) != 0)
            {
                PFAPI.pf_free();
                return false;
            }

            NFAPI.nf_setTCPTimeout(0);

            NF_RULE rule = new NF_RULE();

            // Do not filter local traffic
            rule.filteringFlag = (uint)NF_FILTERING_FLAG.NF_ALLOW;
            rule.ip_family = (ushort)AddressFamily.InterNetwork;
            rule.remoteIpAddress = IPAddress.Parse("127.0.0.1").GetAddressBytes();
            rule.remoteIpAddressMask = IPAddress.Parse("255.0.0.0").GetAddressBytes();
            NFAPI.nf_addRule(rule, 0);

            // Disable QUIC protocol to make the browsers switch to generic HTTP

            NF_RULE_EX ruleEx;

            ruleEx = new NF_RULE_EX();
            ruleEx.protocol = (int)ProtocolType.Udp;
            ruleEx.remotePort = (ushort)IPAddress.HostToNetworkOrder((Int16)80);
            ruleEx.processName = "chrome.exe";
            ruleEx.filteringFlag = (uint)NF_FILTERING_FLAG.NF_BLOCK;
            NFAPI.nf_addRuleEx(ruleEx, 0);

            ruleEx = new NF_RULE_EX();
            ruleEx.protocol = (int)ProtocolType.Udp;
            ruleEx.remotePort = (ushort)IPAddress.HostToNetworkOrder((Int16)443);
            ruleEx.processName = "chrome.exe";
            ruleEx.filteringFlag = (uint)NF_FILTERING_FLAG.NF_BLOCK;
            NFAPI.nf_addRuleEx(ruleEx, 0);

            rule = new NF_RULE();
            // Filter outgoing TCP connections 
            rule.protocol = (int)ProtocolType.Tcp;
            rule.filteringFlag = (uint)NF_FILTERING_FLAG.NF_FILTER;
            NFAPI.nf_addRule(rule, 0);

            return true;
        }
        public void stop()
        {
            NFAPI.nf_free();
            PFAPI.pf_free();
        }
    }
}
