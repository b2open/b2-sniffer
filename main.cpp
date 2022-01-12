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

#include <csignal>
#include <iostream>
#include <getopt.h>
#include <locale.h>

#include <fmt/core.h>
#include <fmt/color.h>
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <fmt/printf.h>

#include "b2sniffer.h"

/* --- Global variables --- */
#define PROC_NAME "b2-sniffer"
#define PROC_VERSION "1.0"

/* --- Static Methods --- */
std::function<void(int)> callback_wrapper = nullptr;
static void signalHandler(int signo)
{
	switch (signo)
	{
	case SIGINT:
		fmt::print(stderr, fmt::emphasis::bold, "\nCaught signal SIGINT, shutting down...\n");
		break;

	case SIGTERM:
		fmt::print(stderr, fg(fmt::color::red)|fmt::emphasis::bold, "\nCaught signal {}, shutting down...\n", signo);
		break;
	default:
		break;
	}	
	
	callback_wrapper(signo);
}

static void setupSignals(void)
{
	struct sigaction action;
	sigset_t mask;

	sigemptyset(&mask);
	action.sa_handler = signalHandler;
	action.sa_mask = mask;
	action.sa_flags = 0;
	sigaction(SIGTERM, &action, nullptr);
	sigaction(SIGINT, &action, nullptr);
}

static void version()
{
	fmt::print(stdout, "{}: {}", PROC_NAME, PROC_VERSION);
}

static void usage(char *prog)
{
	fmt::print(stderr,
			   "Usage: {} [OPTIONS] \n"
			   "\n"
			   "OPTIONS\n"
			   "  -f[ilter],--filter                         enable filter PCAP, export variable FILTER_EXP\n"
			   "  -w[write-pcap],--write-pcap                create pcap file from capture\n"
			   "  -v[erbose],--verbose                       enable mode verbose\n"
			   "  -V[ersion],--version                       show program version\n"
			   "  -h[elp],--help                             print help\n"
			   "\n"
			   "VARIABLES\n"
			   "  FILTER_EXP              use this environment variable to use the --filter option\n"
			   "\n",
			   prog);
}

int main(int argc, char *argv[])
{
	int opt, opt_write_pcap=0, opt_verbose=0;
	const char *filter_exp_env = nullptr;

	static const struct option long_options[] = {
		{"version", 0, nullptr, 'V'},
		{"verbose", 0, nullptr, 'v'},
		{"write-pcap", 0, nullptr, 'w'},
		{"help", 0, nullptr, 'h'},
		{"filter", 0, nullptr, 'f'},
		{nullptr, 0, nullptr, 0}};

	//
	// Set locale to use environment variables
	//
	setlocale(LC_ALL, "");

	//
	// Install Handler Signals
	//
	setupSignals();

	//
	// Parser Options
	//
	while ((opt = getopt_long(argc, argv, "fwvVh",
							  long_options, nullptr)) != EOF)
	{
		switch (opt)
		{
		case 'v':
			opt_verbose++;
			break;

		case 'V':
			version();
			std::exit(EXIT_SUCCESS);

		case 'h':
			usage(argv[0]);
			std::exit(EXIT_SUCCESS);

		case 'f':
			filter_exp_env = getenv("FILTER_EXP");
			if (filter_exp_env == nullptr)
			{
				// Set filter default 'src localhost'
				// 	const char *filter_exp = static_cast<const char *>("src localhost and (src port 33000)");
				filter_exp_env = static_cast<const char *>("src localhost");
			}
			break;

		case 'w':
			opt_write_pcap = 1;
			break;

		case '?':
		default:
			usage(argv[0]);
			std::exit(EXIT_SUCCESS);
		}
	}

	fmt::print(stdout, "Name        : {}\n", PROC_NAME);
	fmt::print(stdout, "Version     : {}\n", PROC_VERSION);
	fmt::print(stdout, "PID:        : {}\n", getpid());
	fmt::print(stdout, "Verbose Mode: {}\n", opt_verbose>0?"ON":"OFF");

	//
	// Register Date Time Started Application
	//
	std::time_t dt = std::time(nullptr);
	fmt::print(stdout, "Started     : {:%Y-%m-%d %H:%M:%S}\n", fmt::localtime(dt));

	//
	// Instance Class Sniffer
	//
	std::shared_ptr<b2::Sniffer> sniffer = std::make_unique<b2::Sniffer>();
	callback_wrapper = std::bind(&b2::Sniffer::catchSignal, sniffer, std::placeholders::_1);

	//
	// Check Capability System CAP_NET_RAW and CAP_NET_ADMIN
	// 
	auto cap_enable = b2::Sniffer::isCapability();
	if (opt_verbose > 0) { fmt::print(stdout, "Capability: {}\n\n", cap_enable); }
	if (!cap_enable) {
		return EXIT_FAILURE;
	}

	//
	// Enable Verbose Mode?
	//
	if (opt_verbose > 0) {
		sniffer->enableVerbose(opt_verbose);
	}

	//
	// Write Pcap File?
	//
	if (opt_write_pcap) {
		sniffer->enableWritePcapFile(true);
	}

	//
	// List and selecting Interface to sniff
	//
	sniffer->listInterfaces();
	
	//
	// Apply filter and run
	//
	int ret;
	ret = sniffer->run(filter_exp_env);
	if (ret > 0)
	{
		fmt::print(stderr, fg(fmt::color::red) | fmt::emphasis::bold, "\nErr Sniffer Running ErroNo[{}]\n", ret);
	}

	return EXIT_SUCCESS;
}
