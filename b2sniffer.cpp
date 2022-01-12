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
#include <fmt/core.h>
#include <fmt/color.h>
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <fmt/printf.h>

#include <net/ethernet.h> 		// ethhdr
// #include <netinet/udp.h>		// udphdr
// #include <netinet/tcp.h>		// tcphdr 
#include <netinet/in.h> 		// defines IPPROTO_TCP, ...
#include <netinet/ip.h>			// iphdr

#include <sys/capability.h>
#include <sys/stat.h>

#include "b2sniffer.h"

using namespace b2;

Sniffer::~Sniffer()
{
	if (m_pcap_handler != nullptr)
	{
		fmt::print(stderr, "\nExit Application, saving pcap and destroying object...\n");
	}
}

int Sniffer::run(const char *filter_exp)
{
	int promiscuous_mode = 1;

	struct bpf_program filter;
	bpf_u_int32 subnet_mask, ip;

	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_lookupnet(m_interface.c_str(), &ip, &subnet_mask, errbuf) == -1)
	{
		fmt::print(stdout, "Could not get information for device: {}\n", m_interface);
		ip = 0;
		subnet_mask = 0;
	}

	//
	// Show Interface Sniff
	//
	fmt::print(stdout, "\n\
-------------------------------\n\
-    Configuration Summary    -\n\
-------------------------------\n");
	//
	// Filter Packet Cap
	//
	if (filter_exp)
	{
		fmt::print(stdout, fmt::emphasis::bold, "\n{:12}", "Filter: ");
		fmt::print(stdout, fmt::emphasis::bold | fmt::fg(fmt::color::orange), "{}\n", filter_exp);
	}
	fmt::print(stdout, fmt::emphasis::bold, "\n{:12}", "Interface: ");
	fmt::print(stdout, fmt::emphasis::bold | fmt::fg(fmt::color::orange), "{}\n", m_interface);

	//
	// Press any key to start capture
	//
	fmt::print(stdout, fmt::emphasis::bold, "\nPress enter key to start capture...");
	std::cin.ignore();
	std::cin.get();

	//
	// Open the device for sniffing
	//
	fmt::print(stdout, fmt::emphasis::bold, "\nOpening device {} for sniffing ...\n", m_interface);
	m_pcap_handler = pcap_open_live(m_interface.c_str(), 65536, promiscuous_mode, 0, errbuf);
	if (m_pcap_handler == nullptr)
	{
		fmt::print(stderr, fg(fmt::color::red) | fmt::emphasis::bold, "\nERROR: ");
		fmt::print(stderr, fg(fmt::color::red), "Couldn't open device [{}]\n{}\n", m_interface, errbuf);
		return EXIT_FAILURE;
	}

	//
	// Filter PCAP
	//
	if (filter_exp)
	{
		//
		// Compile Filter
		//
		fmt::print(stdout, "  Compiler Filter...\n");
		if (pcap_compile(m_pcap_handler, &filter, filter_exp, 0, ip) == -1)
		{
			fmt::print(stderr, fg(fmt::color::red) | fmt::emphasis::bold, "\nERROR: ");
			fmt::print(stderr, fg(fmt::color::red), "Bad filter - {}\n", pcap_geterr(m_pcap_handler));
			return EXIT_FAILURE;
		}

		//
		// Set Filter
		//
		fmt::print(stdout, "  Applying Filter...\n");
		if (pcap_setfilter(m_pcap_handler, &filter) == -1)
		{
			fmt::print(stderr, fg(fmt::color::red) | fmt::emphasis::bold, "\nERROR: ");
			fmt::print(stderr, fg(fmt::color::red), "Error setting filter - {}\n", pcap_geterr(m_pcap_handler));
			return EXIT_FAILURE;
		}
	}

	fmt::print(stdout, fmt::emphasis::bold, "\nPress Ctrl+C to stop capturing...\n");

	//
	// Write Packet Captured
	//
	if (this->m_enable_write_pcap)
	{
		this->writeCaptureFile();
	}

	//
	// Started mainloop
	//
	pcap_loop(m_pcap_handler, -1, processPacket, reinterpret_cast<u_char *>(this));

	//
	// Cleanup
	//
	if (filter_exp)
	{
		pcap_freecode(&filter);
	}

	return EXIT_SUCCESS;
}

void Sniffer::listInterfaces()
{
	char err[PCAP_ERRBUF_SIZE];
	int count = 1, n;
	char devs[25][100];

	pcap_if_t *alldevsp, *device;

	fmt::print(stdout, fmt::emphasis::bold, "\nFinding available devices ...");
	if (pcap_findalldevs(&alldevsp, err) != 0)
	{
		fmt::print(stderr, fg(fmt::color::red) | fmt::emphasis::bold, "\nERROR: ");
		fmt::print(stderr, fg(fmt::color::red), " Finding devices : {}", err);
		std::exit(EXIT_FAILURE);
	}

	fmt::print(stdout, fmt::emphasis::bold, "\nAvailable Devices:\n");

	for (device = alldevsp; device != nullptr; device = device->next)
	{
		if (device->name != nullptr)
		{
			if (device->description != nullptr)
			{
				fmt::print(stdout, "[{:2}] {:15} - {}\n", count, device->name, device->description);
			}
			else
			{
				fmt::print(stdout, "[{:2}] {:15}\n", count, device->name);
			}
			strcpy(devs[count], device->name);
		}
		count++;
	}

	fmt::print(stdout, fmt::emphasis::bold, "\nEnter the number of the device you want to sniff: ");

	scanf("%d", &n);
	if (n > 0 && n < count)
	{
		m_interface = devs[n];
	}
	else
	{
		m_interface = "-";
	}
}

void Sniffer::processPacket(u_char *user, const struct pcap_pkthdr *header, const u_char *buffer)
{
	Sniffer *_sniffer = reinterpret_cast<Sniffer *>(user);
	static int counter_pkt = 0;
	// const size_t size = header->len;

	//
	// TODO: Get TCP Packet Header
	//

	// struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
	const struct iphdr *iph = reinterpret_cast<const struct iphdr *>(buffer + sizeof(struct ethhdr));

	//
	// Selecting the correct protocol for analysis
	//
	switch (iph->protocol)
	{
	case IPPROTO_ICMP:
		// ICMP Protocol
		fmt::print(stdout, "\r[{:5}] ------------------------- ICMP ---------------------", counter_pkt++);
		break;

	case IPPROTO_TCP:
		// TCP Protocol
		fmt::print(stdout, "\r[{:5}] ------------------------- TCP ----------------------", counter_pkt++);
		break;

	case IPPROTO_UDP:
		// UDP Protocol
		fmt::print(stdout, "\r[{:5}] ------------------------- UDP ----------------------", counter_pkt++);
		break;

	default:
		// Other Protocols
		fmt::print(stdout, "\n--------------------------------------------------\n");
		fmt::print(stdout, "  -> Other Protocol: {}\n", iph->protocol);
		fmt::print(stdout, "\n--------------------------------------------------\n");
		break;
	}

	//
	// Write packet in pcap file
	//
	if (_sniffer->m_pcap_dumper != nullptr)
	{
		if (_sniffer->m_enable_verbose > 0)
		{
			fmt::print(stdout, "\t[writePcapFile]");
		}

		//
		// Dump raw packet to file
		//
		pcap_dump((u_char *)_sniffer->m_pcap_dumper, header, buffer);

		//
		// Flush to file
		//
		pcap_dump_flush(_sniffer->m_pcap_dumper);
	}

	std::fflush(stdout);
}

void Sniffer::stats()
{
	struct pcap_stat stat;

	fmt::print(stdout, "\n\
-------------------------------\n\
-        Capture Stats        -\n\
-------------------------------\n");
	if (m_pcap_handler != nullptr)
	{
		if (pcap_stats(m_pcap_handler, &stat) < 0)
		{
			fmt::print(stderr, fg(fmt::color::red) | fmt::emphasis::bold, "\nERROR: ");
			fmt::print(stderr, "pcap_stats: {}\n", pcap_geterr(m_pcap_handler));
		}
		else
		{
			fmt::print(stdout, "{} packets received by filter\n", stat.ps_recv);
			fmt::print(stdout, "{} packets dropped by kernel\n", stat.ps_drop);
		}
	}
}

void Sniffer::catchSignal(int signo)
{
	this->stats();

	if (m_pcap_handler != nullptr)
	{
		if (this->m_enable_verbose > 0)
		{
			fmt::print(stderr, "\nSniffer::catchSignal -> signo[{}]\n", signo);
		}

		//
		// Stop pcap_loop
		//
		pcap_breakloop(m_pcap_handler);

		//
		// Flush and Close Pcap
		//
		if (this->m_enable_write_pcap) {
			pcap_dump_flush(m_pcap_dumper);
			pcap_dump_close(m_pcap_dumper);
		}
	}
}

void Sniffer::writeCaptureFile()
{
	umask(0002);
	char _filename[100];

	//
	// Get current date/time based on current system
	//
	time_t now = time(nullptr);
	tm *_localtime = localtime(&now);

	strftime(_filename, 50, "capture-%d.%m.%Y-%H:%M.pcap", _localtime);

	if (this->m_enable_verbose > 0)
	{
		fmt::print(stdout, "\nPcap File: {}\n", _filename);
	}

	//
	// Open dump device for writing packet capture data. In this sample,
	//
	if ((m_pcap_dumper = pcap_dump_open(m_pcap_handler, _filename)) == nullptr)
	{
		//
		//  Print out error message obtained by pcap_geterr()
		//
		fmt::print(stderr, fg(fmt::color::red) | fmt::emphasis::bold, "\nERROR: ");
		fmt::print(stderr, "opening savefile \"{}\" for writing: {}\n", _filename, pcap_geterr(m_pcap_handler));
	}
}

bool Sniffer::isCapability()
{
	size_t _cap_ok = 0;
	cap_t _caps;
	cap_value_t needed_caps[] = {CAP_NET_ADMIN, CAP_NET_RAW};

	fmt::print(stdout, "\n\
-------------------------------\n\
-       Check Capability      -\n\
-------------------------------\n");

	if (!CAP_IS_SUPPORTED(CAP_NET_ADMIN))
	{
		fmt::print(stderr, fg(fmt::color::red) | fmt::emphasis::bold, "\nERROR: ");
		fmt::print(stderr, "CAP_NET_ADMIN capability not supported on system, aborting...\n");
	}

	_caps = cap_get_proc();
	if (_caps == nullptr)
	{
		fmt::print(stderr, fg(fmt::color::red) | fmt::emphasis::bold, "\nERROR: ");
		fmt::print(stderr, "cap_get_proc() failed, aborting...\n");
	}

	size_t size_nedded_caps = sizeof(needed_caps) / sizeof(needed_caps[0]);
	for (size_t i = 0; i < size_nedded_caps; i++)
	{
		cap_flag_value_t cap_flags_value;
		cap_get_flag(_caps, needed_caps[i], CAP_EFFECTIVE, &cap_flags_value);
		fmt::print(stdout, "[");
		if (cap_flags_value == CAP_SET)
		{
			fmt::print(stdout, fg(fmt::color::lime_green) | fmt::emphasis::bold, "{:5}", "OK");
			_cap_ok++;
		}
		else
		{
			fmt::print(stdout, fg(fmt::color::red) | fmt::emphasis::bold, "{:5}", "ERROR");
		}
		fmt::print(stdout, fmt::emphasis::bold, "] - {:15}\n", cap_to_name(needed_caps[i]));
	}

	if (_cap_ok < size_nedded_caps)
	{
		cap_free(_caps);
		fmt::print(stderr, fg(fmt::color::red) | fmt::emphasis::bold, "\nERROR: ");
		fmt::print(stderr, "cap_set_proc(CAP_SETUID/CAP_SYS_ADMIN) failed, aborting...");
		fmt::print(stderr, fg(fmt::color::lime_green) | fmt::emphasis::bold, "\nFIX: ");
		fmt::print(stdout, "sudo setcap cap_net_raw,cap_net_admin=eip {}\n\n", getenv("_"));

		return false;
	}

	return true;
}

void Sniffer::enableWritePcapFile(bool flag)
{
	m_enable_write_pcap = flag;
}

void Sniffer::enableVerbose(int level)
{
	m_enable_verbose = level;
}
