Description:
	Network analyzer that catches packets and filters them as user sets, after filtering, program shows Time of catch, source address, destination
	address, lenght of packets, offsets, bytes, and ascii value of packets.
Usage:
	./ipk-sniffer [-i interface | --interface interface] {-p port} {[--tcp | -t] [--udp | -u] [--arp] [--icmp]} {-n number}
options:
	-i eth0 | --interface eth0 = use one of those and interface name for choosing interface to listen on, or just -i to get list of available interfaces
	-p 23 = filters all incoming packets by their ports, if senders or receivers port matches given, packet is printed

	-t or --tcp = filters packets by protocol tcp, only receiving tcp
	-u or --udp = same as tcp only with udp
	--icmp = same as tcp only with icmp
	--arp = same as tcp only with arp
	If all of above or none are given, all of protocols will be accepted

	-n 10 = sets how many packets is being catched and filtered

examples:
./ipk-sniffer -i Wi-Fi
2021-04-25T18:36:14.818+00:00  192.168.2.163 > 192.168.2.163 Lenght 60 bytes
Data:  ******* Raw Hex Output - length=60 bytes
Data: Segment:                   Bytes:                              Ascii:
Data: --------------------------------------------------------------------------
Data: 0000  ff ff ff ff ff ff 9c ae  d3 04 58 a6 08 06 00 01   ........ ..X.....
Data: 0010  08 00 06 04 00 01 9c ae  d3 04 58 a6 c0 a8 02 a3   ........ ..X.....
Data: 0020  00 00 00 00 00 00 c0 a8  02 a3 00 00 70 f0 d6 40   ........ ....p..@
Data: 0030  4c f0 d6 40 94 8e 33 40  7c f0 d6 40               L..@..3@ |..@

/////////////////////////////////////////////////////////////////////////////////////

./ipk-sniffer -i WiFi -n 2
2021-04-25T18:37:20.510+00:00  192.168.2.81 > 192.168.2.1 Lenght 42 bytes
Data:  ******* Raw Hex Output - length=42 bytes
Data: Segment:                   Bytes:                              Ascii:
Data: --------------------------------------------------------------------------
Data: 0000  30 d1 6b 8c bc 0d 38 d5  47 b1 c2 30 08 06 00 01   0.k...8. G..0....
Data: 0010  08 00 06 04 00 01 38 d5  47 b1 c2 30 c0 a8 02 01   ......8. G..0....
Data: 0020  00 00 00 00 00 00 c0 a8  02 51                     ........ .Q

2021-04-25T18:37:20.510+00:00  192.168.2.1 > 192.168.2.81 Lenght 42 bytes
Data:  ******* Raw Hex Output - length=42 bytes
Data: Segment:                   Bytes:                              Ascii:
Data: --------------------------------------------------------------------------
Data: 0000  38 d5 47 b1 c2 30 30 d1  6b 8c bc 0d 08 06 00 01   8.G..00. k.......
Data: 0010  08 00 06 04 00 02 30 d1  6b 8c bc 0d c0 a8 02 51   ......0. k......Q
Data: 0020  38 d5 47 b1 c2 30 c0 a8  02 01                     8.G..0.. ..

File list:
	ipk-sniffer.csproj
	Makefile
	PacketDotNet.dll
	Program.cs
	README
	SharpPcap.dll