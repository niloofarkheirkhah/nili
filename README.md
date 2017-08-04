# Nili

![Nili](http://www.upsara.com/images/d296_nili.png)

Nili is a Tool for Network Scan, Fingerprint, Man in the Middle and Fuzzing.

![UI](http://www.upsara.com/images/5vxb_capture.png)

## Prerequisites

* [Python](http://www.dropwizard.io/1.0.2/docs/) - Python Programming Language
* [Scapy](http://www.secdev.org/projects/scapy/) - Interactive Packet Manipulation Program
* [Kivy](https://kivy.org/#home) - Cross Platform Python Framework for GUI Development

## Installing

Nili does not need any Installation, 
Here is some Instructions for Installing Prerequisites, 
Select Proper Instructions for your Operating System and Python Version.

### Unix-like
 
1- Install Python: 

First check if you have Python or not:
```
$ python
```

If you don't:
```
$ sudo apt-get install python
```

2- Install Scapy:

Use pip:
```
$ pip install scapy
```

or:
```
$ cd /tmp
$ wget -O scapy.zip scapy.net
$ unzip scapy.zip
$ cd scapy-master
$ sudo python setup.py install
```

3- Install Kivy:
	
Update Package List:
```
$ sudo apt-get update
```

for Python 2:
```
$ sudo apt-get install python-kivy
```

for Python 3:
```
$ sudo apt-get install python3-kivy
```

### Windows (for Python 2)

1- Install [python-2.17.13](https://www.python.org/ftp/python/2.7.13/python-2.7.13.amd64.msi)
	
2- Install [npcap-0.93](https://nmap.org/npcap/dist/npcap-0.93.exe)
	
3- Install [pyreadline-2.1](https://pypi.python.org/pypi/pyreadline)
	
4- Download [Scapy-2.3.3](https://github.com/secdev/scapy/archive/master.zip)
	
5- Install Scapy:
```
cd scapy-master
python setup.py install
```

6- Upgrade pip and wheel:
```
python -m pip install --upgrade pip wheel setuptools
```

7- Install the Dependencies:
```
python -m pip install docutils pygments pypiwin32 kivy.deps.sdl2 kivy.deps.glew
```

8- Install Kivy:
```
python -m pip install kivy
```

### Windows (for Python 3)

1- Install [python-3.x](https://www.python.org)

2- Install [Winpcap-4.1.3](https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe)

3- Install Scapy3k:
```
python -m pip install scapy-python3
```
	
4- Upgrade pip and wheel:
```
python -m pip install --upgrade pip wheel setuptools
```

5- Install the Dependencies:
```
python -m pip install docutils pygments pypiwin32 kivy.deps.sdl2 kivy.deps.angle
```

6- Install Kivy:
```
python -m pip install kivy	
```

## Authors

* **Niloofar Kheirkhah** - *Initial work* - [niloofarkheirkhah](https://github.com/niloofarkheirkhah)
* **Ehsan Mir** - *Initial work* - [ehsanmir](https://github.com/ehsanmir)

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details
