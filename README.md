# Nili


Nili is a Tool for Network Scan, Fingerprint, Man in the Middle and Fuzzing.

![UI](http://www.upsara.com/images/5vxb_capture.png)

## Prerequisites

* [Python](https://www.python.org) - Python Programming Language
* [Scapy](http://www.secdev.org/projects/scapy) - Interactive Packet Manipulation Program
* [Netzob](https://github.com/netzob/netzob) - Protocol Reverse Engineering, Modeling and Fuzzing

## Installing

Nili does not need any Installation, 
Here is some Instructions for Installing Prerequisites, 
Select Proper Instructions for your Operating System and Python Version.

### Unix-like
 
1- Install Python3 and pip: 

```
$ sudo apt-get install python3
$ sudo apt-get install python3-pip
```

2- Install Scapy:
```
$ cd /tmp
$ git clone https://github.com/phaethon/scapy
$ cd scapy
$ sudo python3 setup.py install
```

3- Install Netzob:
```
$ git clone https://dev.netzob.org/git/netzob
$ cd ./netzob/
$ sudo apt-get install python3 python3-dev python3-setuptools build-essential
$ python3 setup.py install
$ python3 -m pip install bintrees --upgrade
```


### Windows

1- Install [python-3.x](https://www.python.org)

2- Install [Winpcap-4.1.3](https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe)

3- Install Scapy3k:
```
python -m pip install scapy-python3
```

7- Install [Netzob](https://dev.netzob.org/projects/netzob/wiki/Installation_documentation_on_Windows)


## Authors

* **Niloofar Kheirkhah** - *Initial work* - [niloofarkheirkhah](https://github.com/niloofarkheirkhah)
* **Ehsan Mir** - *Initial work* - [ehsanmir](https://github.com/ehsanmir)

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details
