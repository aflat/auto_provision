
import optparse
import sys
import os

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/pexpect_u-2.5-py3.2.egg")
import pexpect

import string
import subprocess
import logging
logging.basicConfig(format='%(message)s', level=logging.DEBUG)

#################################################################################################
##
##	function: runCommand
##	purpose: execs a process, and captures the stdout and stderr into a variable
##	parameters: the command, and all it's parameters as a list
##				workingDir - the directory to run the command in, if not provided, us the current directory
##	returns: the std out and retrun code of the command
##
#################################################################################################
def runCommand(cmd, workingDir="./"):
	logging.debug("\nGoing to run command: " + string.join(cmd))
	process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=workingDir)
	popenOut = process.stdout.read() + process.stderr.read()
	process.wait()
	logging.debug("Command ran, and returned error code: " + str(process.returncode) + "\n")
	return popenOut, process.returncode
#################################################################################################
##
##	function: InstallSalt
##	purpose: installs saltstack minion on the instance, and configures it to be masterless
##	parameters: instanceAddress - the address of the instance we are going to configure
##				instanceUser - the user of the instance we are gong to configure
##				instancePassword - the password of the instance we are gong to configure
##	returns: 
##
#################################################################################################
def InstallSalt(instanceAddress,instanceUser, instancePassword):
	cmd = ['scp', '-vvv', '-o', 'StrictHostKeyChecking=no', '-o', 'GSSAPIAuthentication=no', '-o' ,'UserKnownHostsFile=/dev/null','-i', './id_rsa','./saltstack-salt-el7-epl-7.repo' ,instanceUser+'@'+instanceAddress + ':/etc/yum.repos.d/saltstack-salt-el7-epl-7.repo']
	scpOut, returnCode = runCommand(cmd, "./")

	child = pexpect.spawn ('ssh -o StrictHostKeyChecking=no -o GSSAPIAuthentication=no -o UserKnownHostsFile=/dev/null -i ./id_rsa '+instanceUser + '@' + instanceAddress)
	child.logfile = sys.stdout
	child.expect ('.*]#')
	child.sendline ("yum install -y epel-release")
	child.expect ('.*]#',timeout=210)
	child.sendline ("yum install -y --enablerepo=saltstack-salt-el7 --enablerepo=epel salt-minion")
	child.expect ('.*]#',timeout=210)
	child.sendline ("sed -i 's/#file_client: remote/file_client: local/' /etc/salt/minion")
	child.expect ('.*]#')
	child.sendline ('exit')

#################################################################################################
##
##	function: ConfigureSalt
##	purpose: configures salt by copying the salt config files in
##	parameters: instanceAddress - the address of the instance we are going to configure
##				instanceUser - the user of the instance we are gong to configure
##				instancePassword - the password of the instance we are gong to configure
##	returns: 
##
#################################################################################################
def ConfigureSalt(instanceAddress,instanceUser, instancePassword):

	child = pexpect.spawn ('ssh -o StrictHostKeyChecking=no -o GSSAPIAuthentication=no -o UserKnownHostsFile=/dev/null -i ./id_rsa '+instanceUser + '@' + instanceAddress)
	child.logfile = sys.stdout
	child.expect ('.*]#')
	child.sendline ("mkdir -p /srv/salt")
	child.expect ('.*]#')
	child.sendline ('exit')
	scpFiles = ["salt/top.sls", "salt/webserver.sls", "salt/firewall.sls","salt/httpcontents.sls"]
	for singleFile in scpFiles:
		cmd = ['scp', '-vvv', '-o', 'StrictHostKeyChecking=no', '-o', 'GSSAPIAuthentication=no', '-o' ,'UserKnownHostsFile=/dev/null','-i', './id_rsa',singleFile ,instanceUser+'@'+instanceAddress + ':/srv/' +singleFile]
		scpOut, returnCode = runCommand(cmd, "./")
	
#################################################################################################
##
##	function: RunSalt
##	purpose: executes salt
##	parameters: instanceAddress - the address of the instance we are going to configure
##				instanceUser - the user of the instance we are gong to configure
##				instancePassword - the password of the instance we are gong to configure
##	returns: 
##
#################################################################################################
def RunSalt(instanceAddress,instanceUser, instancePassword):
	child = pexpect.spawn ('ssh -o StrictHostKeyChecking=no -o GSSAPIAuthentication=no -o UserKnownHostsFile=/dev/null -i ./id_rsa '+instanceUser + '@' + instanceAddress)
	child.logfile = sys.stdout
	child.expect ('.*]#')
	child.sendline ("salt-call --local state.highstate")
	child.expect ('.*]#',timeout=210)
	child.sendline ('exit')



parser = optparse.OptionParser(description='Create a www server in AWS')
parser.add_option('--creds', '--c' ,  dest='credsFile',default="aws.creds",
	help='a file containing your aws credentials file, if not supplied it looks for aws.creds')

options, args = parser.parse_args()

#runCmd('ssh -o StrictHostKeyChecking=no -o GSSAPIAuthentication=no -o UserKnownHostsFile=/dev/null root@')
InstallSalt("192.168.1.15","root","mypassword")
ConfigureSalt("192.168.1.15","root","mypassword")
RunSalt("192.168.1.15","root","mypassword")