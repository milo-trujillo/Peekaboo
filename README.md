Peekaboo
========

Peekaboo is a simple port-knocking daemon. It listens for a sequence of ports to be accessed, then runs an arbitrary command.

Options
-------

    Options:
	  -h, --help            show this help message and exit
	  -t TIMEOUT, --timeout TIMEOUT
							Maximum timeout for knocking sequence
	  -u USER, --user USER  User to run commands as if script running as root
	  -s SEQUENCE [SEQUENCE ...], --sequence SEQUENCE [SEQUENCE ...]
							Port knock sequence to listen for

Example Usage
-------------

    sudo ./peekaboo.py -t 20 -u www /tmp/foo -s 1234 2345

The above will listen for knocks on TCP ports 1234 and 2345, then runs the "/tmp/foo" command as the "www" user. Clients get 20 seconds to complete the knock.

Requirements
------------

Peekaboo depends on [Scapy](https://github.com/secdev/scapy), a common Python library for packet analysis.
