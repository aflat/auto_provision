firewall:
    cmd.run:
        - name: firewall-cmd --permanent --zone=public --add-service=http;firewall-cmd --reload