/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstring>
#include <cstdlib>
#include <ctime>
#include <iostream>

#include <pcap.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <unistd.h>

#include <fmt/core.h>
#include <fmt/color.h>
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <fmt/printf.h>

#define PROC_NAME "b2-sniffer"
#define PROC_VERSION "1.0"

static void processPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{	
	int size = header->len;

	//
	// TODO: Get TCP Packet Header
	//
	struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
	
	fmt::print(stdout, "-------------------------\n");
	
	//
	// Selecting the correct protocol for analysis
	//
	switch (iph->protocol)
	{
	// ICMP Protocol
	case 1:
		fmt::print(stdout, "  -> Packet ICMP\n");
		break;

	// TCP Protocol
	case 6:
		fmt::print(stdout, "  -> Packet TCP\n");
		break;

	// UDP Protocol
	case 17:
		fmt::print(stdout, "  -> Packet UDP\n");
		break;

	// Other Protocols
	default:
		fmt::print(stdout, "  -> Other Protocol\n");
		break;
	}
	fmt::print(stdout, "-------------------------\n");
}

int main()
{
	int promiscuous_mode = 1;

	pcap_if_t *alldevsp, *device;
	pcap_t *handler;

	struct bpf_program filter;
	bpf_u_int32 subnet_mask, ip;

	char errbuf[PCAP_ERRBUF_SIZE], *devname, devs[100][100];
	int count = 1, n;

	fmt::print(stdout, "Name     : {}\n", PROC_NAME);
	fmt::print(stdout, "Version  : {}\n", PROC_VERSION);
	fmt::print(stdout, "PID:     : {}\n", getpid());

	//
	// Register Date Time Started Application
	//
	std::time_t dt = std::time(nullptr);
	fmt::print(stdout, "Started  : {:%Y-%m-%d %H:%M:%S}\n", fmt::localtime(dt));

	fmt::print(stdout, fmt::emphasis::bold, "\nFinding available devices ...\n");
	if (pcap_findalldevs(&alldevsp, errbuf))
	{
		fmt::print(stderr, fg(fmt::color::red), "\nError finding devices : {}", errbuf);
		exit(1);
	}

	fmt::print(stdout, fmt::emphasis::bold, "\nAvailable Devices:\n");
	for (device = alldevsp; device != nullptr; device = device->next)
	{
		if (device->name != nullptr)
		{
			if (device->description != nullptr) {
				fmt::print(stdout, "{}. {} - {}\n", count, device->name, device->description);
			} else {
				fmt::print(stdout, "{}. {}\n", count, device->name);
			}
			strcpy(devs[count], device->name);
		}
		count++;
	}

	fmt::print(stdout, "Enter the number of the device you want to sniff : ");
	scanf("%d", &n);
	devname = devs[n];

	if (pcap_lookupnet(devname, &ip, &subnet_mask, errbuf) == -1)
	{
		fmt::print(stdout, "Could not get information for device: {}\n", devname);
		ip = 0;
		subnet_mask = 0;
	}

	//
	// Filter Packt Cap
	//
	char filter_exp[] = "src localhost and (src port 33000)";

	//
	// Open the device for sniffing
	//
	fmt::print(stdout, "Opening device {} for sniffing ...\n", devname);
	handler = pcap_open_live(devname, 65536, promiscuous_mode, 0, errbuf);

	if (handler == nullptr)
	{
		fmt::print(stderr, fg(fmt::color::red), "Couldn't open device {} : {}\n", devname, errbuf);
		exit(1);
	}	

	//
	// Compile Filter
	//
	if (pcap_compile(handler, &filter, filter_exp, 0, ip) == -1)
	{
		fmt::print(stderr, fg(fmt::color::red), "Bad filter - {}\n", pcap_geterr(handler));
		return 2;
	}

	//
	// Set Filter
	//
	if (pcap_setfilter(handler, &filter) == -1)
	{
		fmt::print(stderr, fg(fmt::color::red), "Error setting filter - %s\n", pcap_geterr(handler));
		return 2;
	}

	//
	// Started mainloop
	//
	pcap_loop(handler, -1, processPacket, NULL);

	return 0;
}