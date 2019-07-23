import paramiko,re,sys
import time
def my_ssh(ip,username,password,cmd_list,wait_time=2,verbose=True,port=22):
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip,port,username,password,timeout=5,)
    chan = ssh.invoke_shell()
    for i in cmd_list:
       # stdin ,stdout ,stderr = ssh.exec_command(i)
       # x += stdout.read().decode()
        i += '\n'
        chan.send(i.encode())
        time.sleep(wait_time)
        print(chan.recv(2048).decode())
    ssh.close()

if __name__ == '__main__':
    cmd_list = ['enable','Optus123','sh run | sec snmp-server host','conf ter','snmp-server host 203.202.141.33 version 2c mQQh3vA7k7','end']
    my_ssh('2.4.83.181','source','g04itMua',cmd_list,wait_time=2)
