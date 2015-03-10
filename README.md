# auto_provision


##Usage

You can use 
```
git clone --recursive <this_git_repo>
```
since there is a required submodule, if not, the script will clone for you, hopefully you have the git exe on the path, if you don't, then either run the --recusive clone, or after you clone this repo run
```
git submodule update --init --recursive
```

##Running the script

```
newwww.py --help
```
 will get you the latest help, but here is a copy just in case:
```
Usage: newwww.py [options]

Create a www server in AWS

Options:
  -h, --help            show this help message and exit
  --creds=CREDSFILE, --c=CREDSFILE
                        a file containing your aws credentials file, if not
                        supplied it looks for aws.creds
  --pemfile=PEMNAME, --p=PEMNAME
                        the path to the pem file used to use to connect to the
                        instance, the name in aws,and the local .pem file must
                        have the same name, defaults to ec2-newwww-key.pem.
                        This program will create the key if it doesn't exist
  --testonly, --test    run the test of the url, the script determines the IP
                        of the latest instance that was created and tests
                        itNote: you still need the correct creds in your creds
                        file since this script does some aws searching to find
                        the latest IP
```

##Requirements

A couple of notes:

1. I have only tested on python 2.7, but in theory it should work in 3.3

2. You need a creds file, with the following contents:

[CredentialsSection]
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=

3. If you have an existing .pem key, you can supply it, and the script will attempt to use it, but the key pair in aws must have the same name as the .pem(not counting the .pem extension) eg:
```
python newwww.py --p /home/gstockfisch/.ssh/mylocalkey.pem
```
will use the .pem file there for the ssh/scp calls, but the aws key pair must be "mylocalkey"


