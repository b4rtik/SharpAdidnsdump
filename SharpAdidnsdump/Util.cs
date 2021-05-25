using System;
using System.ComponentModel;
using System.DirectoryServices.ActiveDirectory;
using System.Runtime.InteropServices;

// https://github.com/GhostPack/Rubeus/blob/master/Rubeus/lib/Networking.cs#L12

namespace SharpAdidnsdump
{
    class Util
    {
        public enum SUPPORTED_ETYPE : Int32
        {
            RC4_HMAC_DEFAULT = 0x0,
            DES_CBC_CRC = 0x1,
            DES_CBC_MD5 = 0x2,
            RC4_HMAC = 0x4,
            AES128_CTS_HMAC_SHA1_96 = 0x08,
            AES256_CTS_HMAC_SHA1_96 = 0x10
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DOMAIN_CONTROLLER_INFO
        {
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainControllerName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainControllerAddress;
            public uint DomainControllerAddressType;
            public Guid DomainGuid;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DnsForestName;
            public uint Flags;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DcSiteName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string ClientSiteName;
        }
        [Flags]
        public enum DSGETDCNAME_FLAGS : uint
        {
            DS_FORCE_REDISCOVERY = 0x00000001,
            DS_DIRECTORY_SERVICE_REQUIRED = 0x00000010,
            DS_DIRECTORY_SERVICE_PREFERRED = 0x00000020,
            DS_GC_SERVER_REQUIRED = 0x00000040,
            DS_PDC_REQUIRED = 0x00000080,
            DS_BACKGROUND_ONLY = 0x00000100,
            DS_IP_REQUIRED = 0x00000200,
            DS_KDC_REQUIRED = 0x00000400,
            DS_TIMESERV_REQUIRED = 0x00000800,
            DS_WRITABLE_REQUIRED = 0x00001000,
            DS_GOOD_TIMESERV_PREFERRED = 0x00002000,
            DS_AVOID_SELF = 0x00004000,
            DS_ONLY_LDAP_NEEDED = 0x00008000,
            DS_IS_FLAT_NAME = 0x00010000,
            DS_IS_DNS_NAME = 0x00020000,
            DS_RETURN_DNS_NAME = 0x40000000,
            DS_RETURN_FLAT_NAME = 0x80000000
        }
        [DllImport("Netapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int DsGetDcName(
            [MarshalAs(UnmanagedType.LPTStr)] string ComputerName,
            [MarshalAs(UnmanagedType.LPTStr)] string DomainName,
            [In] int DomainGuid,
            [MarshalAs(UnmanagedType.LPTStr)] string SiteName,
            [MarshalAs(UnmanagedType.U4)] DSGETDCNAME_FLAGS flags,
            out IntPtr pDOMAIN_CONTROLLER_INFO);
        [DllImport("Netapi32.dll", SetLastError = true)]
        public static extern int NetApiBufferFree(IntPtr Buffer);

        public static string GetDCName(string domainName = "")
        {
            // retrieves the current domain controller name

            // adapted from https://www.pinvoke.net/default.aspx/netapi32.dsgetdcname
            DOMAIN_CONTROLLER_INFO domainInfo;
            const int ERROR_SUCCESS = 0;
            IntPtr pDCI = IntPtr.Zero;

            int val = DsGetDcName("", domainName, 0, "",
                DSGETDCNAME_FLAGS.DS_DIRECTORY_SERVICE_REQUIRED |
                DSGETDCNAME_FLAGS.DS_RETURN_DNS_NAME |
                DSGETDCNAME_FLAGS.DS_IP_REQUIRED, out pDCI);

            if (ERROR_SUCCESS == val)
            {
                domainInfo = (DOMAIN_CONTROLLER_INFO)Marshal.PtrToStructure(pDCI, typeof(DOMAIN_CONTROLLER_INFO));
                string dcName = domainInfo.DomainControllerName;
                NetApiBufferFree(pDCI);
                return dcName.Trim('\\');
            }
            else
            {
                try
                {
                    string pdc = Domain.GetCurrentDomain().PdcRoleOwner.Name;
                    return pdc;
                }
                catch
                {
                    string errorMessage = new Win32Exception((int)val).Message;
                    Console.WriteLine("\r\n [X] Error {0} retrieving domain controller : {1}", val, errorMessage);
                    NetApiBufferFree(pDCI);
                    return "";
                }
            }
        }
    }
}
