
// Author: B4rtik (@b4rtik)
// Project: SharpAdidnsdump (https://github.com/b4rtik/SharpAdidnsdump)
// License: BSD 3-Clause
// based on 
// Getting in the zone dumping active directory dns with adidnsdump
// https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/
// by @_dirkjan

using System;
using System.Net;
using System.Net.Sockets;
using System.DirectoryServices;

namespace SharpAdidnsdump
{
    class Program
    {
        static void Main(string[] args)
        {
            String dc_address = "";
            if (args == null || args.Length <= 0)
            {
                Console.WriteLine("usage: SharpAdidnsdumpis.exe dc-address");
                return;
            }
            else
            {
                dc_address = args[0];
            }

            try
            {

                Console.WriteLine("Running enumeration against {0}", dc_address);

                String rootDn = "DC=DomainDnsZones";

                String domain_local = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;

                String domain_path = "";

                foreach (String domain_path_r in domain_local.Split('.'))
                {
                    domain_path += ",DC=" + domain_path_r;
                }

                rootDn += domain_path;

                Console.WriteLine("Running enumeration against {0}", "LDAP://" + dc_address + "/" + rootDn);

                DirectoryEntry rootEntry = new DirectoryEntry("LDAP://" + dc_address + "/" + rootDn);
                rootEntry.AuthenticationType = AuthenticationTypes.Delegation;
                DirectorySearcher searcher = new DirectorySearcher(rootEntry);

                //find domains
                var queryFormat = "(&(objectClass=DnsZone)(!(DC=*arpa))(!(DC=RootDNSServers)))";
                searcher.Filter = queryFormat;
                searcher.SearchScope = SearchScope.Subtree;

                foreach (SearchResult result in searcher.FindAll())
                {
                    String domain = (result.Properties["DC"].Count > 0 ? result.Properties["DC"][0].ToString() : string.Empty);
                    Console.WriteLine();
                    Console.WriteLine();
                    Console.WriteLine("Domain: {0}", domain);
                    Console.WriteLine();

                    DirectoryEntry rootEntry_d = new DirectoryEntry("LDAP://" + dc_address + "/DC=" + result.Properties["DC"][0].ToString() + ",CN=microsoftdns," + rootDn);
                    rootEntry_d.AuthenticationType = AuthenticationTypes.Delegation;
                    DirectorySearcher searcher_h = new DirectorySearcher(rootEntry_d);

                    //find hosts
                    queryFormat = "(&(!(objectClass=DnsZone))(!(DC=@))(!(DC=*arpa))(!(DC=*DNSZones)))";
                    searcher_h.Filter = queryFormat;
                    searcher_h.SearchScope = SearchScope.Subtree;

                    foreach (SearchResult result_h in searcher_h.FindAll())
                    {
                        String target = "";

                        if (result_h.Properties["DC"].Count > 0)
                        {
                            target = result_h.Properties["DC"][0].ToString();
                        }
                        else
                        {
                            //Hidden entry
                            String path = result_h.Path;
                            target = (path.Substring(path.IndexOf("LDAP://" + dc_address + "/"), path.IndexOf(","))).Split('=')[1];
                        }

                        if (!target.EndsWith("."))
                            target += "." + domain;

                        Boolean tombstoned = result_h.Properties["dNSTombstoned"].Count > 0 ? (Boolean)result_h.Properties["dNSTombstoned"][0] : false;

                        try
                        {
                            IPHostEntry hostInfo = Dns.GetHostEntry(target);
                            Console.WriteLine("Host {0} {1}", target, hostInfo.AddressList[0]);
                        }
                        catch (Exception e)
                        {
                            if (tombstoned)
                            {
                                Console.WriteLine("Host {0} Tombstoned", target);
                            }
                            else
                            {
                                Console.WriteLine("DNS Query with target : {0} failed", target);
                            }
                        }
                    }
                }

                Console.WriteLine();
                Console.WriteLine("SharpAdidnsdump end");
                Console.WriteLine();
                return;
            }
            catch (Exception e)
            {
                Console.WriteLine("Error retriving data : {0}", e.Message);
                return;
            }

        }
    }
}

