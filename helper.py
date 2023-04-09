import datetime
import socket
import time
from pathlib import Path

import paramiko
from dcim.models import Device, DeviceRole, Interface
from utilities.exceptions import AbortScript

ipo = f"192.168.1.112"  # Server SSTP orion
ipd = f"192.168.1.117"  # Server SSTP dckz
allow = f"192.168.1.0/24,10.10.10.0/24"
allow1 = f"192.168.1.0/24"
allow2 = f"10.10.10.0/24"
libre = f"192.168.1.111"
passwd_hash = "c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"

srv_device = Device.objects.get(primary_ip4__address=ipo + "/24")
srv_lb = srv_device.interfaces.get(name="Loopback")
router_role = DeviceRole.objects.get(name="Router")


def get_ip_n_mask(device_id):
    sipo, omask = (f"172.16.2.{str(device_id)}", "24")
    sipd, dmask = (f"172.16.6.{str(device_id)}", "24")
    lb, lmask = (f"10.10.10.{str(device_id)}", "24")
    return sipo, omask, sipd, dmask, lb, lmask


def get_ids(device_id):
    return f"1" + str(device_id), f"2" + str(device_id)


def get_timestamp():
    t = datetime.datetime.now()
    return f'{t.strftime("%Y-%m-%d_%H:%M:%S")}'


def get_backup_name(hostname):
    t = get_timestamp()
    return hostname + "_" + t + ".backup"


def get_device_custom_id():
    cfdata = Device.objects.all().values_list("custom_field_data", flat=True)
    ranges = list(range(100, 254))
    for ids in cfdata:
        if ids["IDs"]:
            ranges.remove(ids["IDs"])
    device_id = ranges[0]
    return device_id


def get_custom_eoip_id(existing_id=False):
    cfdata = Interface.objects.all().values_list("custom_field_data", flat=True)
    ranges = list(range(40000, 100000))
    for ids in cfdata:
        if ids["EoIP_id"]:
            ranges.remove(ids["EoIP_id"])
    if existing_id:
        ranges.remove(existing_id)
    eoip_id = ranges[0]
    return eoip_id


def ssh_connect(host, host_ip, srvpasswd, backup_name, commands):
    mt_username = "admin" if str(host_ip) == ipo else host
    mt_password = srvpasswd if str(host_ip) == ipo else "m1kr0tftp"
    timeout = 10

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(
        str(host_ip), username=mt_username, password=mt_password, timeout=timeout
    )
    stdin, stdout, stderr = ssh.exec_command(
        f"system backup save name={backup_name} dont-encrypt=yes"
    )
    time.sleep(2)

    Path(f"/opt/netbox/netbox/{host}_backup").mkdir(parents=True, exist_ok=True)
    sftp = ssh.open_sftp()
    sftp.get(f"/{backup_name}", f"/opt/netbox/netbox/{host}_backup/{backup_name}")
    sftp.close()

    for mt_command in commands:
        stdin, stdout, stderr = ssh.exec_command(mt_command)
        time.sleep(2)

    ssh.get_transport().close()
    ssh.close()

    
def netmiko_ssh_connect(host_ip, username, password, commands):
     mikro1 = {
            "device_type": "mikrotik_routeros",
            "host": host_ip,
            "username": username,
            "password": password,
        }

        with ConnectHandler(**mikro1) as net_connect:
            net_connect.send_config_set(commands, cmd_verify=True)
