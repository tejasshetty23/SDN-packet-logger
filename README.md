# Packet Logger using SDN

##  Overview

This project implements a Software Defined Networking (SDN) controller using Ryu to capture, analyze, and log network packets in real time. Mininet is used to simulate the network topology.


##  Technologies Used

* Python
* Ryu SDN Controller
* Mininet
* OpenFlow 1.3


##  Features

* Captures packets using controller events
* Extracts packet header information (source and destination IP)
* Identifies protocol types (ARP, ICMP, TCP, UDP)
* Stores logs in a CSV file

##  How to Run (On Linux Machines)
A virtual environment is recommended.
To be run on two terminal windows.

### 1. Start the Controller (Terminal 1)

```bash
sudo ~/.pyenv/versions/sdn-env/bin/ryu-manager --ofp-tcp-listen-port 6653 packet_logger.py
```

### 2. Start Mininet (Terminal 2)

```bash
sudo PYTHONPATH=$HOME/mininet ~/mininet/bin/mn --topo linear,3 --controller=remote,ip=127.0.0.1,port=6653
```

Inside Mininet:

```bash
h1 ping h2
```

##  Output

* Real-time packet logs displayed in terminal
* Logs saved in `packet_logs.csv`

  ![](sdn-packet-logger.png)

##  Working

The controller listens for packet-in events from switches.
It extracts packet details, identifies the protocol, logs the data, and forwards packets using OpenFlow rules.

## Author

[Abhiram](https://github.com/abhiram289/)
