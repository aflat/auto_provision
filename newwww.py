#!/usr/bin/python

import optparse
import sys
import os
import ConfigParser

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/pexpect_u-2.5-py3.2.egg")
import pexpect



import datetime
import urllib
import os.path
import string
import subprocess
import logging
import time
logging.basicConfig(format='%(message)s', level=logging.DEBUG)

pexpectEndline = '.*]\$'
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

######Import the aws boto package, 
if(not os.path.isfile(os.path.dirname(os.path.realpath(__file__)) + "/boto/setup.py")):
	logging.info("Boto module not found, git cloning it in...this may take a minute")
	cmd = ['git', 'submodule', 'update', '--init', '--recursive']
	gitOut, returnCode = runCommand(cmd, "./")
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/boto")
import boto.ec2
from boto.vpc import VPCConnection

#################################################################################################
##
##	function: InstallSalt
##	purpose: installs saltstack minion on the instance, and configures it to be masterless
##	parameters: instanceAddress - the address of the instance we are going to configure
##				instanceUser - the user of the instance we are gong to configure
##				keyFile - the location of the keyfile(.pem file)
##	returns: 
##
#################################################################################################
def InstallSalt(instanceAddress,instanceUser, keyFile):
	#we need to add the saltstack .repo file, so we can do the easy yum install later
	cmd = ['scp', '-vvv', '-o', 'StrictHostKeyChecking=no', '-o', 'GSSAPIAuthentication=no', '-o' ,'UserKnownHostsFile=/dev/null','-i', keyFile,'./saltstack-salt-el6-epl-6.repo' ,instanceUser+'@'+instanceAddress + ':/home/ec2-user/saltstack-salt-el6-epl-6.repo']
	scpOut, returnCode = runCommand(cmd, "./")

	#spawn an expect session so we can send commands through ssh
	child = pexpect.spawn ('ssh -o StrictHostKeyChecking=no -o GSSAPIAuthentication=no -o UserKnownHostsFile=/dev/null -i ' +keyFile+ ' '+instanceUser + '@' + instanceAddress)
	child.logfile = sys.stdout
	child.expect (pexpectEndline)

	#salstack needs some extra rpm dependencies located in the epel repo, so download it and install it
	child.sendline ("wget http://download.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm")
	child.expect (pexpectEndline,timeout=210)
	child.sendline ("sudo rpm -ivh epel-release-6-8.noarch.rpm")
	child.expect (pexpectEndline,timeout=210)

	#we can't scp as root into the instance, so it's initially scp'd in as the ec2-user, then once we are ssh'd in we can copy it to the right location
	child.sendline ("sudo mv /home/ec2-user/saltstack-salt-el6-epl-6.repo /etc/yum.repos.d/saltstack-salt-el6-epl-6.repo")
	child.expect (pexpectEndline)

	#there is a bug in the epel repo that gets installed on rhel6, so clean the cache so we can continue
	child.sendline ("sudo yum clean dbcache")
	child.expect (pexpectEndline)

	#finally, install saltstack, as a minion only
	child.sendline ("sudo yum install -y --enablerepo=saltstack-salt-el6 --enablerepo=epel --enablerepo=rhui-REGION-rhel-server-releases-optional salt-minion")
	child.expect (pexpectEndline,timeout=210)
	child.sendline ("sudo sed -i 's/#file_client: remote/file_client: local/' /etc/salt/minion")
	child.expect (pexpectEndline)
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
def ConfigureSalt(instanceAddress,instanceUser, keyFile):

	child = pexpect.spawn ('ssh -o StrictHostKeyChecking=no -o GSSAPIAuthentication=no -o UserKnownHostsFile=/dev/null -i ' + keyFile + ' '+instanceUser + '@' + instanceAddress)
	child.logfile = sys.stdout
	child.expect (pexpectEndline)
	child.sendline ("sudo mkdir -p /srv/salt")
	child.expect (pexpectEndline)
	child.sendline ("sudo chmod 777 /srv/salt")
	child.expect (pexpectEndline)
	child.sendline ('exit')
	#these are all the salt state files that need to be copied in, once we exec salt it will look at them
	scpFiles = ["salt/top.sls", "salt/webserver.sls", "salt/firewall.sls","salt/httpcontents.sls"]
	for singleFile in scpFiles:
		cmd = ['scp', '-vvv', '-o', 'StrictHostKeyChecking=no', '-o', 'GSSAPIAuthentication=no', '-o' ,'UserKnownHostsFile=/dev/null','-i', keyFile,singleFile ,instanceUser+'@'+instanceAddress + ':/srv/' +singleFile]
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
def RunSalt(instanceAddress,instanceUser, keyFile):
	child = pexpect.spawn ('ssh -o StrictHostKeyChecking=no -o GSSAPIAuthentication=no -o UserKnownHostsFile=/dev/null -i' + keyFile + ' '+instanceUser + '@' + instanceAddress)
	child.logfile = sys.stdout
	child.expect (pexpectEndline)

	#this just runs salt, which will check the state files we copied in earlier
	child.sendline ("sudo salt-call --local state.highstate")
	child.expect (pexpectEndline,timeout=210)
	child.sendline ('exit')


#################################################################################################
##
##	Class: AWS
##
#################################################################################################
class AWS(object):
	credsFilename = "aws.creds"
	awsID = ""
	awsSecretKey = ""
	ec2 = None
	vpcConnection = None
	vpc = None
	subnet = None
	subnetAddressRange = "10.10.0.0/24"
	ec2KeyName = None
	gateway = None
	elasticIP = None
	runningInstance = None
	routeTable = None
	ec2KeyPath = None
	instanceTagName = "ec2_newwww_tag"
	
	#################################################################################################
	##
	##	function: __init__
	##	purpose: sets up the initial connection to aws, since all the aws calls need it
	##	parameters: credsFilename - a string which contains the path to the creds file
	##	returns: none
	##
	#################################################################################################
	def __init__(self, credsFilename):
		if( not os.path.isfile(credsFilename) ):
			logging.error("Error: creds file"+credsFilename+ "is missing!!!! exiting ")
			exit(1)
		config = ConfigParser.RawConfigParser()
		config.read(credsFilename)
		self.awsID = config.get('CredentialsSection', 'AWS_ACCESS_KEY_ID')
		self.awsSecretKey = config.get('CredentialsSection', 'AWS_SECRET_ACCESS_KEY')

		
		logging.debug("Using creds file:" + credsFilename)
		#logging.debug("awsID:" + self.awsID)
		#logging.debug("awsSecret:" + self.awsSecretKey)
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
	##	purpose: creates the vpc, using the subnet address range given in self.subnetAddressRange. It also creates the 
	##				internet gateway, and attaches that gateway to the vpc
	##	parameters: none
	##	returns: none
	##
	#################################################################################################
	def CreateVPC(self):
		if(self.vpcConnection == None):
			self.vpcConnection = VPCConnection(aws_access_key_id=self.awsID, aws_secret_access_key=self.awsSecretKey)
		self.vpc = self.vpcConnection.create_vpc(self.subnetAddressRange)
		self.gateway = self.vpcConnection.create_internet_gateway()
		self.vpcConnection.attach_internet_gateway(internet_gateway_id=self.gateway.id, vpc_id=self.vpc.id)
	#################################################################################################
	##
	##	function: CreateSubnet
	##	purpose: creates a subnet, using the subnet address range self.subnetAddressRange
	##	parameters: none
	##	returns: none
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
	##	function: CreateRouteTable
	##	purpose: creates a routetable, with the correct public IP routable
	##	parameters: none
	##	returns: none
	##
	#################################################################################################
	def CreateRouteTable(self):
		if(self.vpcConnection == None):
			self.vpcConnection = VPCConnection(aws_access_key_id=self.awsID, aws_secret_access_key=self.awsSecretKey)
		if(self.vpc == None):
			self.CreateVPC()
		self.routeTable	= self.vpcConnection.create_route_table(self.vpc.id)

	#################################################################################################
	##
	##	function: ModifyRouteTable
	##	purpose: edits the routetable associated with the VPC, to open up all traffic(security hole of course)
	##	parameters: none
	##	returns: none
	##
	#################################################################################################
	def ModifyRouteTable(self):
		if(self.vpcConnection == None):
			self.vpcConnection = VPCConnection(aws_access_key_id=self.awsID, aws_secret_access_key=self.awsSecretKey)
		if(self.vpc == None):
			self.CreateVPC()
		self.routeTable = self.vpcConnection.get_all_route_tables(filters={ 'vpc_id': self.vpc.id })[0]
		self.vpcConnection.create_route(route_table_id=self.routeTable.id, destination_cidr_block="0.0.0.0/0",gateway_id=self.gateway.id)
		
	#################################################################################################
	##
	##	function: ModifySecurityGroup
	##	purpose: edits the security group associated with the VPC, to open up all traffic(security hole of course) 
	##				so all ip addresses hitting port 80 and 22 are accepted
	##	parameters: none
	##	returns: none
	##
	#################################################################################################
	def ModifySecurityGroup(self):
		
		securityGroup = self.ec2.get_all_security_groups(filters={ 'vpc_id': self.vpc.id })[0]
		self.ec2.authorize_security_group(group_id=securityGroup.id,
											from_port="22",
											to_port="22",
											cidr_ip="0.0.0.0/0",
											ip_protocol="tcp")
		self.ec2.authorize_security_group(group_id=securityGroup.id,
											from_port="80",
											to_port="80",
											cidr_ip="0.0.0.0/0",
											ip_protocol="tcp")
		
	#################################################################################################
	##
	##	function: CreateIP
	##	purpose: allocates an elastic ip
	##	parameters: none
	##	returns: none
	##
	#################################################################################################
	def CreateIP(self):
		if(self.elasticIP == None):
			self.elasticIP = self.ec2.allocate_address('vpc')
	#################################################################################################
	##
	##	function: RunInstance
	##	purpose: this gets the instance running. it makes sure the subnet and vpc are created so it can attach them
	##				to the instance. It will wait for the instance to go to the running state, and then it will 
	##				attach the elastic IP. Trying to do that too early in instance creation can cause a failure
	##				After that, it creates a couple of tags for the instance, so we can look them up later when we do tests
	##	parameters: none
	##	returns: bot.ec2.instance.Reservation object
	##
	#################################################################################################
	def RunInstance(self):
		
		#amiID = "ami-96a818fe" #this is centos7, but comes from the marketplace, 
								#so if you haven't agreed to the marketplace agreement, you can't launch it
		amiID = "ami-48400720" #redhat ami id
		if(self.subnet == None):
			self.CreateSubnet()
		if(self.elasticIP == None):
			self.CreateIP()
		if(self.vpc == None):
			self.CreateVPC()
		
		if( not os.path.isfile(self.ec2KeyPath)): 
			logging.debug("need to create the the keypair: " + self.ec2KeyName)
			key_pair = self.ec2.create_key_pair(self.ec2KeyName)
			key_pair.save('./')
		#print self.ec2.run_instances.__doc__
		
		self.runningInstance = self.ec2.run_instances(image_id=amiID, 
										key_name=self.ec2KeyName, 
										instance_type="t2.micro",
										#security_group_ids=['sg-dfa62ebb'],
										subnet_id=self.subnet.id
										)
		#make sure you sleep before associating the IP, AWS can fail if you don't
		instanceStatus = self.runningInstance.instances[0].update()
		while instanceStatus == 'pending':
			logging.info("Instance is still pending, waiting(10 seconds) for it to move on from that state...")
			time.sleep(10)
			instanceStatus = self.runningInstance.instances[0].update()

		#make sure you wait before associating the IP, AWS can fail if you don't
		instanceStatus = self.runningInstance.instances[0].update()
		while instanceStatus != 'running':
			logging.info("Instance is not in a running state, waiting for it...")
			time.sleep(10)
			instanceStatus = self.runningInstance.instances[0].update()

		#Name the instance we just started, and create a tag with the current timestamp, so we can search for it later when we run tests
		self.ec2.create_tags(resource_ids=[self.runningInstance.instances[0].id], tags={"Name": self.instanceTagName,
																	"EpochDateCreated":str(time.time())})   
		#cheating since I only create 1 instance, I know it's [0]
		self.ec2.associate_address(allocation_id=self.elasticIP.allocation_id, instance_id=self.runningInstance.instances[0].id,public_ip=self.elasticIP.public_ip)
		return self.runningInstance
	#################################################################################################
	##
	##	function: FindLatestInstance
	##	purpose: finds the latest instance which contains the name self.instanceTagName
	##	parameters: none
	##	returns: the public IP of the (hopefully) running instance
	##
	#################################################################################################
	def FindLatestInstance(self):

		allInstances = self.ec2.get_only_instances(filters={'tag:Name':[self.instanceTagName]})
		if(allInstances == None):
			logging.error("Failed to get any instance with a tag Name of: " + self.instanceTagName + " I can't run a test")
			return 1

		#we should have at least 1 instance, so we can assign that now
		latestReservation = [allInstances[0].id,allInstances[0].tags["EpochDateCreated"],allInstances[0].ip_address]

		#the iterate through all the instances that have the right name, and see which one is newest, 
		#I'm assuming the newest one is the one we want to test, the others might just be terminated
		for singleInstance in allInstances:
			if(singleInstance.tags["EpochDateCreated"] > latestReservation[1]):
				latestReservation = [singleInstance.id, singleInstance.tags["EpochDateCreated"],singleInstance.ip_address]
		return latestReservation[2]

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

	#################################################################################################
	##
	##	function: GetPemKeyFileName
	##	purpose: gets the name of the pem key file
	##	parameters: none
	##	returns: a string containing the location of the pem key
	##
	#################################################################################################
	def GetPemKeyFileName(self):
		return self.ec2KeyPath
	#################################################################################################
	##
	##	function: GetPublicIP
	##	purpose: gets the public IP of the instance we just created
	##	parameters: none
	##	returns: a string containing the location of the pem key
	##
	#################################################################################################
	def GetPublicIP(self):
		return self.elasticIP.public_ip
	#################################################################################################
	##
	##	function: SetKeyName
	##	purpose: sets the keyname(the aws "Key Pair"), and path(to the local .pem file) we are going to use to connect to the instance with, 
	##	parameters: none
	##	returns: 
	##
	#################################################################################################
	def SetKeyNameAndPath(self, keyPath="ec2-newwww-key.pem"):
		
		if(os.path.splitext( os.path.basename(keyPath))[1] != ".pem" and not os.path.isfile(keyPath)):
			logging.error("ERROR: your .pem file doesn't exist, and the filename you supplied doesn't end in .pem, you need to" +
				" either supply an existing filename, or pass in a filename with a .pem extension, exiting")
			exit(1)
		self.ec2KeyName = os.path.splitext( os.path.basename(keyPath))[0]
		self.ec2KeyPath = keyPath
		
	#################################################################################################
	##
	##	function: CheckInstanceStatus
	##	purpose: checks the status of the instance we just started, so we can tell when it is running
	##	parameters: none
	##	returns: a string - the status of the instance
	##
	#################################################################################################
	def CheckInstanceState(self):

		#print self.ec2.__doc__
		print self.runningInstance.instances[0].__doc__
		return self.runningInstance.instances[0].state

######END of AWS class



#################################################################################################
##
##	function: TestURL
##	purpose: tests the url to make sure we get a 200 response
##	parameters: url: string - the full url to get, including the http://
##	returns: 0 on success, 1 on failure
##
#################################################################################################
def TestURL(url):
	logging.info("Testing url: " + url + " please wait....")
	if (urllib.urlopen(url).getcode() == 200):
		logging.info("URL: " + url + " is up and running, feel free to visit")
		return 0
	logging.error("URL: " + url + " is NOT up there was an error somewhere")
	return 1


#####Main

parser = optparse.OptionParser(description='Create a www server in AWS')
parser.add_option('--creds', '--c' ,  dest='credsFile',default="aws.creds",
	help='A file containing your aws credentials file, if not supplied it looks for aws.creds')
parser.add_option('--pemfile', '--p' ,  dest='pemName',default="ec2-newwww-key.pem",
	help="The path to the pem file used to use to connect to the instance, the name in aws,"+
			"and the local .pem file must have the same name, defaults to ec2-newwww-key.pem. " +
			"This program will create the key if it doesn't exist\n")
parser.add_option('--testonly', '--test' , action="store_true", dest='testOnly',default=False,
	help="Run the test of the url, the script determines the IP of the latest instance that was created and tests it"+
			"Note: you still need the correct creds in your creds file since this script does some aws searching to find the latest IP")


options, args = parser.parse_args()





aws = AWS(options.credsFile)
if (options.testOnly == True):
	logging.info("Running test only...")
	latestIp = aws.FindLatestInstance()
	if(TestURL("http://" + latestIp) == 0):
		logging.info("Testing passed!")
		exit(0)
	logging.error("Error: Testing failed!")
	exit(1)

aws.SetKeyNameAndPath(options.pemName)
runningInstance = aws.RunInstance()
aws.ModifyRouteTable()
aws.ModifySecurityGroup()
#There isn't much of a way to make sure the OS is running(since the AWS class already knows it's in a running state),
#so I'm coping out and sleeping, 60 seconds might be long, but it works. I could try to ping, 
#or ssh until it doesn't timeout, but that can hit it's own issues 
logging.info("Going to wait 60 seconds for the OS in the instance to start up")
for x in range(1,7):
	logging.info("I'm not hung, sleep cycle(10 seconds each) " + str(x) + " of 6")
	time.sleep(10)

InstallSalt(aws.GetPublicIP(),"ec2-user",aws.GetPemKeyFileName() )
ConfigureSalt(aws.GetPublicIP(),"ec2-user",aws.GetPemKeyFileName() )
RunSalt(aws.GetPublicIP(),"ec2-user",aws.GetPemKeyFileName())

TestURL("http://"+aws.GetPublicIP())

