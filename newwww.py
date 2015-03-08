
import optparse
import sys
import os
import ConfigParser

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/pexpect_u-2.5-py3.2.egg")
import pexpect

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/boto")
import boto.ec2
from boto.vpc import VPCConnection

import os.path
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

class AWS(object):
	credsFilename = "aws.creds"
	awsID = ""
	awsSecretKey = ""
	ec2 = None
	vpcConnection = None
	vpc = None
	subnet = None
	subnetAddressRange = "10.10.0.0/24"
	
	def __init__(self, credsFilename):
		config = ConfigParser.RawConfigParser()
		config.read(credsFilename)
		self.awsID = config.get('CredentialsSection', 'AWS_ACCESS_KEY_ID')
		self.awsSecretKey = config.get('CredentialsSection', 'AWS_SECRET_ACCESS_KEY')

		
		logging.debug("got creds file:" + credsFilename)
		logging.debug("awsID:" + self.awsID)
		logging.debug("awsSecret:" + self.awsSecretKey)
		if( len(self.awsID) == 0 or len(self.awsSecretKey) == 0):
			logging.error("ERROR: You must provide your AWS crendentials in the file " + credsFilename)
			sys.exit(1)

		self.ec2 = boto.connect_ec2(aws_access_key_id=self.awsID, aws_secret_access_key=self.awsSecretKey)
		if(self.ec2 == None):
			logging.error("ERROR: Failed to connect to the ec2 instance with the given creds in file: " + credsFilename)
			sys.exit(1)	


	#################################################################################################
	##
	##	function: CreateVPC
	##	purpose: creates the vpc
	##	parameters: 
	##	returns: none
	##
	#################################################################################################
	def CreateVPC(self):
		if(self.vpcConnection == None):
			self.vpcConnection = VPCConnection(aws_access_key_id=self.awsID, aws_secret_access_key=self.awsSecretKey)
		self.vpc = self.vpcConnection.create_vpc(self.subnetAddressRange)
	#################################################################################################
	##
	##	function: CreateSubnet
	##	purpose: creates a subnet
	##	parameters: 
	##	returns: the subnet object
	##
	#################################################################################################
	def CreateSubnet(self):
		if(self.vpcConnection == None):
			self.vpcConnection = VPCConnection(aws_access_key_id=self.awsID, aws_secret_access_key=self.awsSecretKey)
		if(self.vpc == None):
			self.CreateVPC()
		self.subnet = self.vpcConnection.create_subnet(self.vpc.id, self.subnetAddressRange)

	#################################################################################################
	##
	##	function: RunInstance
	##	purpose: initializes a aws connection
	##	parameters: 
	##	returns: 
	##
	#################################################################################################
	def RunInstance(self):
		ec2KeyName = "ec2-newwww-key"
		#amiID = "ami-96a818fe" #this is centos7, but comes from the marketplace, 
								#so if you haven't agreed to the marketplace agreement, you can't launch it
		amiID = "ami-48400720" #redhat ami id
		if(self.subnet == None):
			self.CreateSubnet()
		
		if( not os.path.isfile(ec2KeyName + ".pem")): 
			logging.debug("need to create the the keypair: " + ec2KeyName)
			key_pair = ec2.create_key_pair(ec2KeyName)
			key_pair.save('./')
		#print self.ec2.run_instances.__doc__
		
		reservation = self.ec2.run_instances(image_id=amiID, 
										key_name=ec2KeyName, 
										instance_type="t2.micro",
										#security_group_ids=['sg-dfa62ebb'],
										subnet_id=self.subnet.id
										)
	#################################################################################################
	##
	##	function: GetCreds
	##	purpose: gets the aws credentials from the aws.creds file
	##	parameters: none
	##	returns: a hashmap of keyID,secretKey
	##
	#################################################################################################
	def GetCreds(self):
		return awsID,awsSecretKey




parser = optparse.OptionParser(description='Create a www server in AWS')
parser.add_option('--creds', '--c' ,  dest='credsFile',default="aws.creds",
	help='a file containing your aws credentials file, if not supplied it looks for aws.creds')

options, args = parser.parse_args()

aws = AWS(options.credsFile)
aws.RunInstance()
#aws.RunInstance()
#awsID,awsSecretKey = GetAWSCreds(options.credsFile)
#RunAWSInstance(awsID, awsSecretKey)
#InstallSalt("192.168.1.15","root","mypassword")
#ConfigureSalt("192.168.1.15","root","mypassword")
#RunSalt("192.168.1.15","root","mypassword")