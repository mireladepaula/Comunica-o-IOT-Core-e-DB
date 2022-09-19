import json
import paramiko
import sys

def lambda_handler(event, context):
    

    host_ip='3.231.203.45'
    host_port=3306
    username='ec2-user'
    pkey_path="lambda_kp.pem"
    
    

    key=paramiko.RSAKey.from_private_key_file(pkey_path)
    

    ssh=paramiko.SSHClient()

   
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    

    ssh.connect(hostname=host_ip, username=username, pkey=key)
    

    stdin, stdout, stderr = ssh.exec_command('ls -al')
    

    for line in stdout.read().splitlines():
        print(line.decode("utf-8"))

    ssh.close()