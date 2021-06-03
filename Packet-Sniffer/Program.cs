using System;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Collections.Generic;
using System.Linq;

namespace ipk_sniffer
{
    class Program
    {   //creating few needed global variables for callback function
        private static int packet_received = 0;           //variable storing count of received packets    
        private static int packets_to_receive = 1;        //variable storing number of packets to receive
        private static int port_up = -1;                  //variable with default port out of range
        private static List<string> protocols_used = new List<string>();    //list of protocols
        static void Main(string[] args)
        {
            int i = 0;
            LibPcapLiveDevice device = null;
            CaptureDeviceList devices = CaptureDeviceList.Instance;     //creating list of our devices (interfaces)
        
            while (i < args.Length)     //while for parsing arguments given
            {
                if (args[i] == "-i" || args[i] == "--interface")    //interface selector detection
                {

                    if (args.Length <= i + 1)       //checking if there is following argument
                    {
                        foreach (LibPcapLiveDevice dev in devices)  //there is no following argument so we print available devices
                            Console.WriteLine("{0}\n", dev.Interface.FriendlyName); 
                        System.Environment.Exit(0);
                    }   
                    foreach (LibPcapLiveDevice dev in devices)
                    {
                        if (args[i + 1] == dev.Interface.FriendlyName)  //checking if given interface is in our available devices
                        {
                            device = dev;                              
                            i++;
                            break;
                        }
                    }
                }
                else if (args[i] == "-n")   //checking for next possible argument given
                {
                    int.TryParse(args[i + 1], out packets_to_receive);
                }
                else if (args[i] == "-t")
                    protocols_used.Add("Tcp");
                else if (args[i] == "--tcp")
                    protocols_used.Add("Tcp");
                else if (args[i] == "--udp")
                    protocols_used.Add("Udp");
                else if (args[i] == "-u")
                    protocols_used.Add("Udp");
                else if (args[i] == "--icmp")
                    protocols_used.Add("Icmp");
                else if (args[i] == "--arp")
                    protocols_used.Add("Arp");
                else if (args[i] == "-p")
                    int.TryParse(args[i + 1], out port_up);
                i++;
            }
            if (protocols_used.Count == 0)  //if there was no given protocol, we use all of them
            {
                protocols_used.Add("Tcp");
                protocols_used.Add("Udp");
                protocols_used.Add("Icmp");
                protocols_used.Add("Arp");
            }
            if (device != null)
            {
                device.OnPacketArrival +=  //setting callback function
                    new PacketArrivalEventHandler(device_OnPacketArrival);
            }
            else
            {
                foreach (LibPcapLiveDevice dev in devices)  //printing devices if given device was not found
                    Console.WriteLine("{0}\n", dev.Interface.FriendlyName);
                System.Environment.Exit(0);
            }

            device.Open(mode: DeviceMode.Promiscuous);  //opening device connection

            device.StartCapture();      //start of capturing packets

        }


        /// <summary>
        /// Prints the time and length of each received packet
        /// </summary>
        private static void device_OnPacketArrival(object sender, CaptureEventArgs e)   //call back function called on each packet
        {
            if (packet_received == packets_to_receive)      //if max number of packets was received, exit 
                System.Environment.Exit(0);

            
            var time = e.Packet.Timeval.Date;
            var len = e.Packet.Data.Length;
            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data); 
            var ipPacket = packet.Extract<PacketDotNet.IPPacket>();     //extracting ip packet values
            var sender_ip = new System.Net.IPAddress(new byte[] { 0, 0, 0, 0 });    
            var receiver_ip = new System.Net.IPAddress(new byte[] { 0, 0, 0, 0 });



            if (ipPacket != null && protocols_used.Contains(ipPacket.Protocol.ToString()) == true)  //checking if ip packet is actually an arp packet
            {
                sender_ip = ipPacket.SourceAddress;
                receiver_ip = ipPacket.DestinationAddress;
                if (protocols_used.Contains("Tcp") == true && ipPacket.Protocol.ToString() == "Tcp")    //checking if protocol we use is tcp
                {
                    var tcpPacket = packet.Extract<PacketDotNet.TcpPacket>();
                    var sender_port = tcpPacket.SourcePort;
                    var receiver_port = tcpPacket.DestinationPort;
                    if (port_up != -1 && (sender_port == port_up || receiver_port == port_up))//checking if receivers or senders port matches given port (if given)
                    {
                        Console.WriteLine("{0} {1} : {2} > {3} : {4} Lenght {5} bytes",
                    time.ToString("yyyy-MM-dd'T'HH:mm:ss.fffzzz ", System.Globalization.DateTimeFormatInfo.InvariantInfo), receiver_ip, receiver_port, sender_ip, sender_port, len);
                        Console.WriteLine(packet.PrintHex()); 
                        packet_received++;
                    }
                }
                else if (protocols_used.Contains("Udp") == true && ipPacket.Protocol.ToString() == "Udp")
                {
                    var udpPacket = packet.Extract<PacketDotNet.UdpPacket>();
                    var sender_port = udpPacket.SourcePort;
                    var receiver_port = udpPacket.DestinationPort;
                    if (port_up != -1 && (sender_port == port_up || receiver_port == port_up)) //checking if receivers or senders port matches given port (if given)
                    {
                        Console.WriteLine("{0} {1} : {2} > {3} : {4} Lenght {5} bytes",
                    time.ToString("yyyy-MM-dd'T'HH:mm:ss.fffzzz ", System.Globalization.DateTimeFormatInfo.InvariantInfo), receiver_ip, receiver_port, sender_ip, sender_port, len);
                        Console.WriteLine(packet.PrintHex());
                        packet_received++;
                    }
                }
                else if (protocols_used.Contains("Icmp") == true || protocols_used.Contains("IcmpV6") == true)
                {
                    var IcmpPacket = packet.Extract<PacketDotNet.UdpPacket>();
                    Console.WriteLine("{0} {1} > {2} Lenght {3} bytes",
                time.ToString("yyyy-MM-dd'T'HH:mm:ss.fffzzz ", System.Globalization.DateTimeFormatInfo.InvariantInfo), receiver_ip, sender_ip, len);
                    Console.WriteLine(packet.PrintHex());
                    packet_received++;
                }
            }
            else if (ipPacket == null && protocols_used.Contains("Arp") == true)
            {
                var arpPacket = packet.Extract<PacketDotNet.ArpPacket>();
                if (arpPacket != null)
                {
                    sender_ip = arpPacket.SenderProtocolAddress;
                    receiver_ip = arpPacket.TargetProtocolAddress;
                    Console.WriteLine("{0} {1} > {2} Lenght {3} bytes",
                    time.ToString("yyyy-MM-dd'T'HH:mm:ss.fffzzz ", System.Globalization.DateTimeFormatInfo.InvariantInfo), receiver_ip, sender_ip, len);
                    Console.WriteLine(packet.PrintHex());
                    packet_received++;
                }
            }
            
            
        }
    }
}
