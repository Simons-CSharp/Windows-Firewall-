/*
 * Basic Firewall Control. Simon Page
 * Add Firewall blocking using ranges from text file
 * text files in c:\IT Security\IP Ranges
 * list from https://www.ip2location.com/free/visitor-blocker
 * Output format Config Server Firewall
 */
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NetFwTypeLib;

namespace IP_Range_Blocker
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Starting Firewall Program...");
            //
            //Find Text files in C:\IP Security\IP Ranges
            //Text format for a range xxx.xxx.xxx.xxx-xxx.xxx.xxx.xxx
            //or
            //Text format for a single IP address xxx.xxx.xxx.xxx
            //Both are accepted by Firewall API
            //
            string[] FileList = System.IO.Directory.GetFiles("C:\\IT Security\\IP Ranges");
            int LineRead = 0;
            int RulesAdded = 0;
            foreach (string FileNameAndPath in FileList)
            {
                using (System.IO.StreamReader sr = new System.IO.StreamReader(FileNameAndPath))
                {
                    string[] JustTheFileName = System.IO.Path.GetFileNameWithoutExtension(FileNameAndPath).Split(' ');
                    while (!sr.EndOfStream)
                    {
                        string IPRange = sr.ReadLine();
                        LineRead++;

                        if (BlockThisIP(IPRange, JustTheFileName[0]))
                        {
                            RulesAdded++;
                        }
                    }


                    sr.Close();
                }
            }
            Console.WriteLine("Read {0} Entries. Added {1} Rules", LineRead, RulesAdded);

            Console.ReadKey();
        }

        static bool BlockThisIP(string IpAddress, string Description)
        {
            try
            {
                //ipaddress is:
                Console.WriteLine("Range to be added to Firewall:{0}", IpAddress);

                Type tNetFwPolicy2 = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(tNetFwPolicy2);
                var currentProfiles = fwPolicy2.CurrentProfileTypes;

                // Let's create a new rule
                INetFwRule2 inboundRule = (INetFwRule2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                inboundRule.Enabled = true;
                //Allow through firewall
                inboundRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                //Using protocol ANY
                inboundRule.Protocol = (int)NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_ANY;
                 //Name of rule
                inboundRule.Name = Description + "_" + IpAddress;
                inboundRule.RemoteAddresses = IpAddress; //"255.255.255.255-255.255.255.255" for a range or single IP
                inboundRule.InterfaceTypes = "ALL";
                inboundRule.Description = Description + " " + DateTime.Now.ToString("yyyy-MM-dd hh:mm:ss"); //Blocked from this date
                                                                                        // inboundRule.Profiles = currentProfiles;

                // Now add the rule
                INetFwPolicy2 firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                firewallPolicy.Rules.Add(inboundRule);

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Err:" + ex.Message);
                return false;
            }
        }

        #region "Utilities"
        static bool DoesFirewallRuleExist(string Ip)
        {
            //Looks for IP address in the firewall rules
            //returns true if found, false if not found
            Type tNetFwPolicy2 = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(tNetFwPolicy2);

            foreach (INetFwRule rule in fwPolicy2.Rules.Cast<INetFwRule>().ToList())
            {
                if (rule.Name.Contains(Ip))
                {
                    return true;
                }
            }

            return false;

        }
        static bool RemoveRuleForIp(string Ip)
        {
            //Removes rule with Ip address
            try
            {
                Type tNetFwPolicy2 = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(tNetFwPolicy2);

                bool rtn = false;

                foreach (INetFwRule rule in fwPolicy2.Rules.Cast<INetFwRule>().ToList())
                {
                    if (rule.LocalAddresses.Contains(Ip))
                    {
                        fwPolicy2.Rules.Remove(rule.Name);
                        rtn = true;
                    }
                }

                return rtn;
            }
            catch(Exception ex)
            {
                Console.WriteLine("REmove Rule Threw exception:{0}", ex.Message);
                return false;
            }
        }
        #endregion
    }
}
