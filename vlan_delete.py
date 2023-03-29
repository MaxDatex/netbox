from dcim.models import Device, Interface, DeviceRole
from ipam.models import VLAN
from extras.scripts import Script, ObjectVar, MultiObjectVar, MultiChoiceVar, BooleanVar, StringVar
from django.db.models import Q
from jinja2 import StrictUndefined, Environment
from utilities.exceptions import AbortScript
from pathlib import Path
import paramiko
import socket
import time
import hashlib
import datetime

COMMANDS_TEMPLATE = '''
{% for number in numbers %}
/interface bridge port remove number={{ number }}
{% endfor %}
{% for interface in interfaces %}
/interface vlan remove {{ interface }}
{% endfor %}
'''

# {% if del_bridge %}
# /interface bridge remove Br_{{ vid }}
# {% endif %}


def _get_numbers(ssh, vid, interfaces):
    commands_applied = True
    tmp = 'filler'
    numbers = list()
    try:
        stdin, stdout, stderr = ssh.exec_command(f'interface bridge port print where bridge=Br_{vid}')
        time.sleep(2)
        for line in stdout:
            if f'Br_{vid}' in line and tmp[1].isnumeric() and any(
                    [inter[:10] in line for inter in list(interfaces.values_list('name', flat=True))]):
                numbers.append(tmp[1])
            tmp = line
    except Exception as e:
        raise AbortScript(e)
    return commands_applied, numbers


router_role = DeviceRole.objects.get(name="Router")
t = datetime.datetime.now()
t1 = f'{t.strftime("%Y-%m-%d_%H:%M:%S")}'


class VlanDelete(Script):
    class Meta:
        name = 'Vlan Delete'

    device = ObjectVar(
        model=Device,
        query_params={
            "role_id": router_role.id
        }
    )

    srvpasswd = StringVar(
        label='Пароль сервера'
    )

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

    # vids = set(device.interfaces.values_list('tagged_vlans__vid', flat=True)) & \
    #        set(device.interfaces.values_list('untagged_vlan__vid', flat=True))
    # vids.discard(None)

    vlan = ObjectVar(
        model=VLAN
    )

    # del_bridge = BooleanVar(default=False)

    def run(self, data, commit):
        server_ip = '192.168.1.112/24'
        host = data["device"]
        host_ip = host.primary_ip.address.ip
        vlan = data["vlan"]
        interfaces = data["interfaces"]
        interface_names = interfaces.values_list('name', flat=True)
        vid = vlan.vid
        srvpasswd = data["srvpasswd"]
        t1 = f'{t.strftime("%Y_%m_%d_%H_%M_%S")}'
        backup_name = host + "_" + t1 + '.backup'

        passwd_hash = 'c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec'
        if hashlib.sha512(srvpasswd.encode('UTF-8')).hexdigest() != passwd_hash:
            raise AbortScript("Password is incorrect")

        if not Device.objects.get(id=host.id).interfaces.filter(
                Q(tagged_vlans__name__contains=vlan.name) |
                Q(untagged_vlan=vlan)
        ):
            raise AbortScript(f'Vlan {vlan.name} doesn\'t exists in {host.name}')

        if not Interface.objects.filter(id__in=interfaces).filter(
                Q(tagged_vlans__name__contains=vlan.name) |
                Q(untagged_vlan=vlan)
        ):
            raise AbortScript(f'Vlan {vlan.name} doesn\'t exists on interfaces {[name for name in interfaces.values_list("name", flat=True)]}')

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        numbers = _get_numbers(ssh, vid, interfaces)

        data_to_render = {
            # 'vid': vid,
            'interfaces': interfaces,
            # 'del_bridge': del_bridge,
            'numbers': numbers
        }

        jenv = Environment(undefined=StrictUndefined, trim_blocks=True)
        jtemplate = jenv.from_string(COMMANDS_TEMPLATE)

        commands = jtemplate.render(data_to_render)

        # delete interfaces for client
        mt_username = 'admin' if str(host_ip) == server_ip[:-3] else host.name
        mt_password = srvpasswd if str(host_ip) == server_ip[:-3] else "m1kr0tftp"
        timeout = 10

        try:
            ssh.connect(str(host_ip), username=mt_username, password=mt_password, timeout=timeout)
            stdin, stdout, stderr = ssh.exec_command(f'system backup save name={backup_name} dont-encrypt=yes')
            time.sleep(2)

            Path(f'/opt/netbox/netbox/{host}_backup').mkdir(parents=True, exist_ok=True)
            sftp = ssh.open_sftp()
            sftp.get(f'/{backup_name}', f'/opt/netbox/netbox/{host}_backup/{backup_name}')
            sftp.close()

            for mt_command in commands.splitlines():
                stdin, stdout, stderr = ssh.exec_command(mt_command)
                time.sleep(2)

        except socket.timeout:
            raise AbortScript('Device not reachable! Check routers from/to NB')
        except paramiko.ssh_exception.AuthenticationException:
            raise AbortScript(f'Auth failed, {mt_username}, {mt_password}')
        except paramiko.SSHException:
            raise AbortScript('Failed to run commands')
        except Exception as e:
            raise AbortScript(e)

        ssh.get_transport().close()
        ssh.close()

        for interface in interfaces:
            if interface.type == 'virtual' and interface.name.startswith(f'vlan_{vid}'):
                interface.delete()
            else:
                interface.bridge = None
                if interface.untagged_vlan:
                    interface.untagged_vlan = None
                    interface.mode = ''
                    interface.save()
                if interface.tagged_vlans.all() and vlan in interface.tagged_vlans.all():
                    interface.tagged_vlans.remove(vlan)
                    interface.save()
        # if del_bridge:
        #     bridge.delete()
        #     self.log_info(f'Bridge interface {bridge.name} have been deleted')
        self.log_info(f'Interfaces {", ".join(interface_names)} were deleted')

        # if del_bridge:
        #     server = Device.objects.get(primary_ip4__address=server_ip)
        #     out_int = server.interfaces.get(name=f'vlan_{vid}_bond_{host}')
        #     out_int.delete()
        #     self.log_info(f'Interface {out_int} deleted')

        return
