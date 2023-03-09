from dcim.models import Device, Interface
from extras.scripts import Script, ObjectVar, BooleanVar, StringVar
from django.db.models import Q
from netmiko import ConnectHandler
import hashlib


class Otkat(Script):
    class Meta:
        name = 'Otkat'

    device = ObjectVar(model=Device)

    srvpasswd = StringVar(label='Пароль серверу')

    rmv_lb = BooleanVar(label='Видалити Loopback?')

    def run(self, data, commit):
        srvpasswd = data["srvpasswd"]
        passwd_hash = 'c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec'
        if hashlib.sha512(srvpasswd.encode('UTF-8')).hexdigest() != passwd_hash:
            self.log_failure('Невірний пароль сервера')
            return passwd_hash

        orion_ip = '192.168.1.112/24'
        rmv_lb = data["rmv_lb"]
        host = data["device"].name
        device = Device.objects.get(name=host)
        ids = device.custom_field_data['IDs']
        client_interfaces = device.interfaces.filter(
            Q(name='Bond_main') |
            Q(name__istartswith='eoip-dckz') |
            Q(name__istartswith='eoip-orion') |
            Q(name__istartswith='sstp-orion') |
            Q(name__istartswith='sstp-dckz')
        )

        for interface in client_interfaces:
            interface.delete()
        if rmv_lb:
            try:
                lb = device.interfaces.get(name='Loopback')
                lb.delete()
            except Interface.DoesNotExist:
                pass

        srv_device = Device.objects.get(primary_ip4__address=orion_ip)
        srv_interfaces = srv_device.interfaces.filter(name__icontains=f'{host}')
        for interface in srv_interfaces:
            interface.delete()

        commands = [
            f'interface eoip remove EoIP-orion_1{ids}',
            f'interface eoip remove EoIP-dckz_2{ids}',
            f'interface bonding remove bond_{host}',
            f'interface vlan remove vlan_47_bond_{host}'
        ]

        mikro1 = {
            "device_type": "mikrotik_routeros",
            "host": orion_ip[:-3],
            "username": "admin+ct",
            "password": srvpasswd,
        }

        with ConnectHandler(**mikro1) as net_connect:
            net_connect.send_config_set(commands, cmd_verify=True)
        output = str(commands)

        return output
