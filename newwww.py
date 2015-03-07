
import optparse

import logging
logging.basicConfig(format='%(message)s', level=logging.DEBUG)



parser = optparse.OptionParser(description='Create a www server in AWS')
parser.add_option('--creds', '--c' ,  dest='credsFile',default="aws.creds",
	help='a file containing your aws credentials file, if not supplied it looks for aws.creds')

options, args = parser.parse_args()