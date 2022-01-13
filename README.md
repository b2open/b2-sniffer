# b2-sniffer

[![CircleCI](https://circleci.com/gh/b2open/b2-sniffer/tree/main.svg?style=svg)](https://circleci.com/gh/b2open/b2-sniffer/tree/main)

Simple sniffer in C++ with libpcap para capturar/capturar e salvar pcap file.
Use wireshark to view the generated .pcap files.

# Clone Project
```
$ git clone --recurse-submodules git@github.com:b2open/b2-sniffer.git
Cloning into 'b2-sniffer'...
remote: Enumerating objects: 48, done.
remote: Counting objects: 100% (48/48), done.
remote: Compressing objects: 100% (32/32), done.
remote: Total 48 (delta 17), reused 38 (delta 11), pack-reused 0
Receiving objects: 100% (48/48), 85.03 KiB | 0 bytes/s, done.
Resolving deltas: 100% (17/17), done.
Checking connectivity... done.
Submodule '3rdparty/fmt' (https://github.com/fmtlib/fmt) registered for path '3rdparty/fmt'
Cloning into '3rdparty/fmt'...
remote: Enumerating objects: 28366, done.
remote: Counting objects: 100% (1105/1105), done.
remote: Compressing objects: 100% (312/312), done.
remote: Total 28366 (delta 687), reused 1035 (delta 642), pack-reused 27261
Receiving objects: 100% (28366/28366), 13.76 MiB | 6.11 MiB/s, done.
Resolving deltas: 100% (19122/19122), done.
Checking connectivity... done.
Caminho do sub-módulo '3rdparty/fmt': confirmado '7bdf0628b1276379886c7f6dda2cef2b3b374f0b'
```

# Compile
```
$ cd b2-sniffer/
b2-sniffer $ mkdir build
b2-sniffer $ cd build/
b2-sniffer/build $ cmake ../
...
b2-sniffer/build $ make
Scanning dependencies of target fmt
[ 16%] Building CXX object 3rdparty/fmt/CMakeFiles/fmt.dir/src/format.cc.o
[ 33%] Building CXX object 3rdparty/fmt/CMakeFiles/fmt.dir/src/os.cc.o
[ 50%] Linking CXX static library libfmt.a
[ 50%] Built target fmt
Scanning dependencies of target b2-sniffer
[ 66%] Building CXX object CMakeFiles/b2-sniffer.dir/main.cpp.o
[ 83%] Building CXX object CMakeFiles/b2-sniffer.dir/b2sniffer.cpp.o
[100%] Linking CXX executable b2-sniffer
[100%] Built target b2-sniffer

b2-sniffer/build $ ./b2-sniffer -V
b2-sniffer: 1.0
```

# Dependencies
- libpcap
- libcap

# Export Filter Expression
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


Roadmap
-------
    - Display during capture the eth header
    - Display during capture the ip header
    - Display during capture the tcp and udp header
    - Display during captura the payload packet

Contact
-------
You can contact me by email at cleitonrbueno@gmail.com.
