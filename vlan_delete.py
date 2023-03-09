from dcim.models import Device, Interface
from ipam.models import VLAN
from extras.scripts import Script, ObjectVar, MultiObjectVar, MultiChoiceVar, BooleanVar
from django.db.models import Q
from netmiko import ConnectHandler
from jinja2 import StrictUndefined, Environment
import paramiko
import socket
import traceback
import time


COMMANDS_TEMPLATE = '''
{% if del_bridge %}
/interface bridge remove Br_{{ vid }}
{% endif %}
/interface vlan remove vlan_{{ vid }}_Bond_main
{% for number in numbers %}
/interface bridge port remove number={{ number }}
{% endfor %}
'''


class VlanDelete(Script):
    class Meta:
        name = 'Vlan Delete'

    device = ObjectVar(model=Device)

    bridge_interface = ObjectVar(
        model=Interface,
        query_params={
            'device_id': '$device',
            'type': 'bridge',
            'name__n': 'Loopback'
        }
    )

    interfaces = MultiObjectVar(
        model=Interface,
        query_params={
            'device_id': '$device',
            'bridge_id': '$bridge_interface'
        }
    )

    vlan = ObjectVar(model=VLAN)

    del_bridge = BooleanVar(default=False)

    def run(self, data, commit):
        server_ip = '192.168.1.112/24'
        host = data["device"]
        host_ip = host.primary_ip.address.ip
        vlan = data["vlan"]
        bridge = data["bridge_interface"]
        interfaces = data["interfaces"]
        del_bridge = data["del_bridge"]
        vid = vlan.vid

        if not Device.objects.get(id=host.id).interfaces.filter(
                Q(tagged_vlans__name__contains=vlan.name) |
                Q(untagged_vlan=vlan)
        ):
            self.log_failure(f'Vlan {vlan.name} doesn\'t exists in {host.name}')
            return f'Vlan {vlan.name} didn\'t exists in {host.name}'

        if not Interface.objects.filter(id__in=interfaces).filter(
                Q(tagged_vlans__name__contains=vlan.name) |
                Q(untagged_vlan=vlan)
        ):
            self.log_failure(
                f'Vlan {vlan.name} doesn\'t exists on interfaces {[name for name in interfaces.values_list("name", flat=True)]}'
            )
            return f'Vlan {vlan.name} doesn\'t exists on interfaces {[name for name in interfaces.values_list("name", flat=True)]}'

        mik1 = {
            "device_type": "mikrotik_routeros",
            "ip": server_ip[:-3],
            "username": "admin+ct",
            "password": "admin",
        }
        commands_applied = True

        # delete interfaces for server
        try:
            with ConnectHandler(**mik1) as net_connect:
                net_connect.send_command(f'/interface vlan remove vlan_{vid}_bond_{host}')
                net_connect.send_command(f'/interface vlan remove vlan_{vid}_ether1')
        except Exception:
            commands_applied = False
            self.log_failure(traceback.format_exc())
            return traceback.format_exc()

        # delete interfaces for client
        mt_username = host.name
        mt_password = "m1kr0tftp"
        timeout = 10

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(str(host_ip), username=mt_username, password=mt_password, timeout=timeout)

        except socket.timeout:
            self.log_failure(traceback.format_exc())
            commands_applied = False
            return traceback.format_exc()

        # get numbers of interfaces in bridge
        tmp = 'filler'
        numbers = list()
        try:
            stdin, stdout, stderr = ssh.exec_command(f'interface bridge port print where bridge=Br_{vid}')
            time.sleep(2)
            for line in stdout:
                if f'Br_{vid}' in line and tmp[1].isnumeric():
                    numbers.append(tmp[1])
                tmp = line
        except Exception:
            self.log_failure(traceback.format_exc())
            commands_applied = False
            return traceback.format_exc()

        data_to_render = {
            'vid': vid,
            'interfaces': interfaces,
            'del_bridge': del_bridge,
            'numbers': numbers
        }

        jenv = Environment(undefined=StrictUndefined, trim_blocks=True)
        jtemplate = jenv.from_string(COMMANDS_TEMPLATE)

        commands = jtemplate.render(data_to_render)

        try:
            for mt_command in commands.splitlines():
                stdin, stdout, stderr = ssh.exec_command(mt_command)
                time.sleep(2)
        except Exception:
            self.log_failure(traceback.format_exc())
            commands_applied = False
            return traceback.format_exc()

        ssh.get_transport().close()
        ssh.close()

        if not commands_applied:
            return 'Commands not applied!'

        for interface in interfaces:
            if interface.type == 'virtual' and interface.name.startswith(f'vlan_{vid}'):
                self.log_info(f'Interface {interface.name} deleted')
                interface.delete()
            else:
                self.log_info(f'Bridge from interface {interface.name} have been deleted')
                interface.bridge = None
                if interface.untagged_vlan:
                    self.log_info(f'Untagged VLAN {vlan.name} from interface {interface} have been removed')
                    interface.untagged_vlan = None
                    interface.mode = ''
                    interface.save()
                if interface.tagged_vlans.all() and vlan in interface.tagged_vlans.all():
                    self.log_info(f'Tagged VLAN {vlan.name} from interface {interface} have been removed')
                    interface.tagged_vlans.remove(vlan)
                    interface.save()
        if del_bridge:
            self.log_info(f'Bridge interface {bridge.name} have been deleted')
            bridge.delete()

        self.log_info(vid)
        server = Device.objects.get(primary_ip4__address=server_ip)
        ether1 = server.interfaces.get(name='ether1')
        ether1.tagged_vlans.remove(vlan)
        ether1.save()
        in_int = server.interfaces.get(name=f'vlan_{vid}_ether1')
        in_int.delete()
        out_int = server.interfaces.get(name=f'vlan_{vid}_bond_{host}')
        out_int.delete()

        return
