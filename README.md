# PortScanDetector
Linux port scan detector. Will add a rule to iptables or firewalld to log TCP packets and ban them if they hit more than 10 ports.

## Requires 
- [Python 2.7](https://www.python.org/download/releases/2.7/)

## Useage
Make sure to set isIpTables to True or False depending on your system. Currently only supports iptables and firewalld.

`$ sudo python scanDetector.py`
