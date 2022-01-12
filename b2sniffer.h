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
#ifndef B2SNIFFER_HPP
#define B2SNIFFER_HPP

#include <iostream>
#include <string>
#include <unistd.h>
#include <utility>
#include <pcap.h>

namespace b2
{
    class Sniffer
    {
    public:
        Sniffer() = default;
        ~Sniffer();

        int run(const char* filter_exp);

        void listInterfaces();

        std::string interface() const { return m_interface; }
        
        void interface(std::string &ifname) { m_interface = ifname; }

        void stats();

        void catchSignal(int signo);

        static bool isRoot() { return getuid()==0; }

        static bool isCapability();

        void enableWritePcapFile(bool flag);

        void enableVerbose(int level);

    private:
        std::string m_interface;
        pcap_t *m_pcap_handler;
        pcap_dumper_t *m_pcap_dumper={nullptr};
        bool m_enable_write_pcap={false};
        int m_enable_verbose=0;

        static void processPacket(u_char *user, const struct pcap_pkthdr *header, const u_char *buffer);        

        void writeCaptureFile();
    };
}

#endif // B2SNIFFER_HPP