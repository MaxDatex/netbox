from dcim.models import Device, Interface
from extras.scripts import Script, ObjectVar, BooleanVar, StringVar
from netmiko import ConnectHandler
import hashlib
import paramiko
import socket
import traceback


class DeleteDevice(Script):
    class Meta:
        name = 'Delete device'

    device = ObjectVar(model=Device)

    srvpasswd = StringVar(label='Пароль серверу')

    def run(self, data, commit):
        orion_ip = '192.168.1.112/24'
        srvpasswd = data["srvpasswd"]
        passwd_hash = 'c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec'
        if hashlib.sha512(srvpasswd.encode('UTF-8')).hexdigest() != passwd_hash:
            self.log_failure('Невірний пароль сервера')
            return

        host = data["device"]
        ids = host.custom_field_data['IDs']
        host_ip = host.primary_ip4.address.ip

        mt_username = host.name
        mt_password = "m1kr0tftp"
        timeout = 10

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(str(host_ip), username=mt_username, password=mt_password, timeout=timeout)

        except socket.timeout:
            return traceback.format_exc()

        try:
            stdin, stdout, stderr = ssh.exec_command('system reset-configuration no-defaults=yes skip-backup=yes')
        except Exception:
            return traceback.format_exc()

        host.delete()

        srv_device = Device.objects.get(primary_ip4__address=orion_ip)
        srv_interfaces = srv_device.interfaces.filter(name__icontains=f'{host.name}')
        for interface in srv_interfaces:
            interface.delete()

        commands = [
            f'interface eoip remove EoIP-orion_1{ids}',
            f'interface eoip remove EoIP-dckz_2{ids}',
            f'interface bonding remove bond_{host.name}',
            f'interface vlan remove vlan_47_bond_{host.name}'
        ]

        mikro1 = {
            "device_type": "mikrotik_routeros",
            "host": orion_ip[:-3],
            "username": "admin+ct",
            "password": srvpasswd,
        }

        try:
            with ConnectHandler(**mikro1) as net_connect:
                net_connect.send_config_set(commands, cmd_verify=True)
        except Exception:
            return traceback.format_exc()

        output = str(commands)
        return output
