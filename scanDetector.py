#!/usr/bin/env python

import re
import os
import subprocess

isIptables = False


def iptables():
  if '-A INPUT -p tcp -j LOG --log-prefix " INPUT TCP "' not in subprocess.check_output(["iptables", "-S"]):
    print "Rule not there"
    # rule = '-A INPUT -p tcp -j LOG --log-prefix " INPUT TCP " '
    subprocess.call(
      ['iptables', '-A', 'INPUT', '-p', 'tcp', '-j', 'LOG', '--log-prefix', ' INPUT TCP ', '--log-level', '4'])


def firewalld():
  if 'rule family="ipv4" source NOT address="0.0.0.0" log prefix="INPUT TCP " accept' not in subprocess.check_output(
    ["firewall-cmd", "--list-all-zones"]):
    print "Rule not there"
    # rule = '-A INPUT -p tcp -j LOG --log-prefix " INPUT TCP " '
    os.system(
      'firewall-cmd --add-rich-rule=\'rule family="ipv4" source address=0.0.0.0 invert="true" log prefix="INPUT TCP " accept\'')


def isInFirewall(ip):
  if isIptables:
    if ip in subprocess.check_output(["iptables", "-S"]):
      return True
  else:
    if ip in subprocess.check_output(["firewall-cmd", "--list-all-zones"]):
      return True
  return False


def banIp(ip):
  print "BANNING:", ip
  if isIptables:
    subprocess.call(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
  else:
    os.system('firewall-cmd --add-rich-rule=\'rule family="ipv4" source address="' + ip + '" drop\'')


if isIptables:
  iptables()
else:
  firewalld()

try:
  log = open("/var/log/kern.log", "r")
except:
  log = open("/var/log/messages", "r")

ips = {}
for line in log:
  if "INPUT TCP" in line:
    match = re.match(r'^(\w*  ?\d* \d*:\d*:\d*) .* INPUT TCP .* SRC=(\S*) .* DPT=(\d*) .*$', line)
    if match is None:
      continue
    timestamp = match.group(1)
    ip = match.group(2)
    port = match.group(3)
    found = False
    for key, value in ips.iteritems():
      if ip == key:
        if port not in ips[key]:
          ips[key].append(port)
        found = True

    if found == False:
      ips[ip] = [port]

for key, value in ips.iteritems():
  if not isInFirewall(key):
    banIp(key)
