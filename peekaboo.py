#!/usr/bin/env python

import time, os, sys, argparse, pwd, grp
from scapy.all import *

username = None
maxAge = None
sequence = []
command = None
clients = dict()

# Many systems require root access for packet sniffing, but we probably
# don't want to be running any commands as root. Drop to whatever user
# has been requested before we run anything.
def dropPrivileges():
	if( os.getuid() != 0 or username == None ):
		return
	uid = pwd.getpwnam(username).pw_uid
	gid = pwd.getpwnam(username).pw_gid

	# Remove existing groups
	os.setgroups([])

	# And set the new credentials
	# Note: Set GID *first* so we still have root power to set uid after
	os.setgid(gid)
	os.setuid(uid)

def trigger(addr):
	pid = os.fork()
	if( pid == 0 ): # Child
		dropPrivileges()
		# We *should* use exec here, but that requires parsing the command
		# to split arguments, and getting the path to the executable
		ret = os.system(command)
		sys.exit(ret)

def clearOldKnocks():
	global clients
	now = int(time.strftime("%s"))
	clients = {k: v for k,v in clients.iteritems() if (now - v[0] <= maxAge)}

def addKnock(addr, port):
	now = int(time.strftime("%s"))
	clearOldKnocks()
	if( addr in clients ):
		numEntered = len(clients[addr])
		# Make sure this is the next knock in the sequence
		if( port == sequence[numEntered] ):
			clients[addr] += [now]
		else:
			del clients[addr]
			return
		if( len(clients[addr]) == len(sequence) ):
			trigger(addr)
	# First knock
	else:
		if( port == sequence[0] ):
			clients[addr] = [now]

def process(packet):
	src = packet[1].src
	port = packet[2].dport
	if( port in sequence ):
		addKnock(src, port)
	# Sequence broken
	elif( src in clients ):
		del clients[src]

class Parser(argparse.ArgumentParser):
	def error(self, message):
		sys.stderr.write("error: %s\n" % message)
		self.print_help()
		sys.exit(2)

def parseOptions():
	global maxAge
	global sequence
	global command
	global username
	descr = "A trivial port knocker."
	parser = Parser(description=descr)
	parser.add_argument("-t", "--timeout",
		action="store", type=int, dest="maxAge", default=10,
		metavar="TIMEOUT", help="Maximum timeout for knocking sequence")
	parser.add_argument("-u", "--user",
		action="store", type=str, dest="user", default=None,
		metavar="USER", help="User to run commands as if script running as root")
	parser.add_argument("-s", "--sequence",
		action="store", nargs="+", type=int, required=True, dest="sequence",
		metavar="SEQUENCE", help="Port knock sequence to listen for")
	parser.add_argument("command", metavar="<command>", nargs=1,
		help="Command to run on successful port knock")
	options = parser.parse_args()
	sequence = options.sequence
	command = options.command[0]
	username = options.user
	maxAge = options.maxAge

if __name__ == "__main__":
	parseOptions()
	sniff(filter="tcp", prn=process)
