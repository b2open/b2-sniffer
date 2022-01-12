# b2-sniffer
Simple sniffer in C++ with libpcap para capturar/capturar e salvar pcap file.
Use wireshark to view the generated .pcap files.

To add a filter use the `FILTER_EXP` environment variable, for example:

```sh
$ export FILTER_EXP="src localhost and (src port 33000)"
```

## Options

```bash
$ ./b2-sniffer --help
Usage: ./b2-sniffer [OPTIONS]

OPTIONS
  -f[ilter],--filter                         enable filter PCAP, export variable FILTER_EXP
  -w[write-pcap],--write-pcap                create pcap file from capture
  -v[erbose],--verbose                       enable mode verbose
  -V[ersion],--version                       show program version
  -h[elp],--help                             print help

VARIABLES
  FILTER_EXP              use this environment variable to use the --filter option
```

## Tests
   * Server
```bash
$ python3 tests/serverTCP.py
```

   * Client
```bash
$ bash tests/clientTCP.sh
```


## Printscreen
![picture](https://raw.githubusercontent.com/b2open/b2-sniffer/main/images/img1.png)

