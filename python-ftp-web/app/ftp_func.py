import os
import random
import string
import subprocess

storage_server = "192.168.1.121"
storage_username = "root"

ssh = "ssh " + storage_username + "@" + storage_server

def generate_password(length):
    result_str = ''.join(random.choice(string.ascii_letters) for i in range(length))
    print(result_str)
    return result_str

def create_ftp_user(username, _password): #create quota
    os.system('{ssh} "useradd -m {0}"'.format(username, ssh=ssh))
    os.system('{ssh} "echo {0}:{1} | chpasswd {0}"'.format(username, _password, ssh=ssh))
    os.system('{ssh} "usermod -a -G ftp {0}"'.format(username, ssh=ssh))
    os.system('{ssh} "echo {0} >> /etc/vsftpd.user_list"'.format(username, ssh=ssh))
    os.system('{ssh} "mkdir /home/{0}/ftp_dir"'.format(username, ssh=ssh))
    os.system('{ssh} "chmod -R 750 /home/{0}/ftp_dir"'.format(username, ssh=ssh))
    os.system('{ssh} "chown -R {0}: /home/{0}/ftp_dir"'.format(username, ssh=ssh))
    os.system('{ssh} "setquota -u {0} 10G 10G 0 0 /"'.format(username, ssh=ssh))

def get_current_quota(username):
    command =  "quota -vs %s" % username
    awk = "| tail -1 | awk '{print $3}'"
    quota = subprocess.check_output('{ssh} "{0}" {1}'.format(command, awk, ssh=ssh ), shell=True)
    return quota.decode("utf-8").strip()

def get_used_space(username):
    command =  "quota -vs %s" % username
    awk = "| tail -1 | awk '{print $2}'"
    quota = subprocess.check_output('{ssh} "{0}" {1}'.format(command, awk, ssh=ssh ), shell=True)
    return quota.decode("utf-8").strip()

def set_quota(username, quota):
    os.system('{ssh} "setquota -u {0} {1} {1} 0 0 /"'.format(username, quota, ssh=ssh))

def ftp_lock(username):
    cmd = "sed -i -e 's/%s//' /etc/vsftpd.user_list" % username
    os.system('{ssh} "{0}"'.format(cmd, ssh=ssh))

def ftp_unlock(username):
    cmd = "echo %s >> /etc/vsftpd.user_list" % username
    os.system('{ssh} "{0}"'.format(cmd, ssh=ssh))

def ftp_chpasswd(username, password):
    os.system('{ssh} "echo {0}:{1} | chpasswd {0}"'.format(username, password, ssh=ssh))