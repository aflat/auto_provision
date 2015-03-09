base:
  '*':
    - webserver
    #my centos test server had the firewall enabled, so I wrote a state to open it up, 
    #aws uses security groups instead of instance firewalls
    #- firewall
    - httpcontents