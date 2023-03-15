import datetime
import socket
import time
import traceback
import hashlib

import paramiko
from dcim.models import Device, Interface
from extras.scripts import Script, ObjectVar, MultiObjectVar, StringVar
from ipam.models import VLAN
from jinja2 import Environment, StrictUndefined
from tenancy.models import *

COMMANDS_TEMPLATE = '''/interface bridge add name=Br_{{ vid }} comment=from_NB_{{ timestamp }}
{% for trunk_port in trunks %}
/interface vlan add interface={{ trunk_port }} name=vlan_{{ vid }}_{{ trunk_port }} vlan-id={{ vid }} disable=no comment=from_NB_{{ timestamp }}
/interface bridge port add bridge=Br_{{ vid }} interface=vlan_{{ vid }}_{{ trunk_port }} comment=from_NB_{{ timestamp }}
{% endfor %}
{% for access_port in access %}
/interface bridge port add bridge=Br_{{ vid }} interface={{ access_port }} comment=from_NB_{{ timestamp }}
{% endfor %}
'''

t = datetime.datetime.now()
t1 = f'{t.strftime("%Y-%m-%d_%H:%M:%S")}'


class RunCommand(Script):
    class Meta:
        name = "VLAN"
        description = "Set VLAN"

    device = ObjectVar(
        model=Device,
        description=' ТЕСТ ',
        label='Name Dev',
        required=True
    )

    srvpasswd = StringVar(
        label='Пароль сервера'
    )

    iin = MultiObjectVar(
        model=Interface,
        label='trunk ports VLAN',
        query_params={
            'device_id': '$device',
            'mode__n': 'access',
        }
    )

    iout = MultiObjectVar(
        required=False,
        model=Interface,
        label='Access ports VLAN',
        query_params={
            'device_id': '$device',
            'mode__n': 'access',
            'interface_id__n': '$iin'
        }
    )

    vlan_id = ObjectVar(
        model=VLAN,
        label='VLAN (ID)',
        required=True
        )

    def run(self, data, commit):

        host = f'{data["device"].name}'
        host_ip = data["device"].primary_ip.address.ip
        vid = f'{data["vlan_id"].vid}'
        vlan_object = data.get('vlan_id')
        trunk_interfaces = data.get('iin')
        access_interfaces = data.get('iout')

        srvpasswd = data["srvpasswd"]
        passwd_hash = 'c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec'
        if hashlib.sha512(srvpasswd.encode('UTF-8')).hexdigest() != passwd_hash:
            self.log_failure('Невірний пароль сервера')
            return passwd_hash

        # check that acc ports does not have intersection with trunk ports
        for acc_port in access_interfaces:
            if acc_port in trunk_interfaces:
                self.log_failure(f'Error: access port {acc_port} have intersection with trunk ports')
                return

        data_to_render = {
            'vid': vid,
            'trunks': [i.name for i in trunk_interfaces],
            'access': [i.name for i in access_interfaces],
            'timestamp': t1
        }

        jenv = Environment(undefined=StrictUndefined, trim_blocks=True)
        jtemplate = jenv.from_string(COMMANDS_TEMPLATE)

        commands = jtemplate.render(data_to_render)

#########################################################

        mt_username = 'admin' if str(host_ip) == '192.168.1.112' else host
        mt_password = srvpasswd if str(host_ip) == '192.168.1.112' else "m1kr0tftp"
        timeout = 10

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        commands_applied = True

        try:
            ssh.connect(str(host_ip), username=mt_username, password=mt_password, timeout=timeout)

        except socket.timeout:
            with open("error.log", "a") as f:
                f.write(t1 + " " + host + " Timeout connecting to the device.\n")
            commands_applied = False
            return traceback.format_exc(), mt_username, mt_password
        except paramiko.ssh_exception.AuthenticationException:
            return f'Auth failed\n, {mt_username}, {mt_password}'

        try:
            for mt_command in commands.splitlines():
                stdin, stdout, stderr = ssh.exec_command(mt_command)
                time.sleep(2)
        except Exception:
            commands_applied = False
            return traceback.format_exc()

        ssh.get_transport().close()
        ssh.close()

        html_template = """ <p>
                        <a href="https://nb.rona.best/extras/scripts/disable_Eoip_bond_mik.RunCommand/">у майбутньому </a>
                            </p>
                        """

        self.log_info(html_template)

        html_template2 = """ <p>
                        <a href="https://nb.rona.best/extras/scripts/disable_Eoip_bond_mik.RunCommand/">у майбутньому </a>
                             </p>
                         """

        self.log_info(html_template2)

#################################################################

        # create NetBox objects if commands applied
        if commands_applied and commit:

            bridge_name = f'Br_{vid}'
            device = data.get('device')

            # 1. create bridge interface
            bridge_interface, _ = device.interfaces.get_or_create(type='bridge', name=bridge_name)
            # 2.1 for all trunk ports create virtual inteface like vlan_{vid}_{interface}
            if trunk_interfaces:
                for trunk_port in trunk_interfaces:
                    vint_name = f'vlan_{vid}_{trunk_port.name}'
                    # 2.2 set parent for virtual interface as trunk_port
                    virtual_interface, _ = device.interfaces.get_or_create(type='virtual', name=vint_name, parent=trunk_port)
                    # 2.3 set untagged vlan
                    virtual_interface.untagged_vlan = vlan_object
                    virtual_interface.mode = 'access'
                    # 2.4 set tagged vlan to trunk port
                    trunk_port.tagged_vlans.add(vlan_object)
                    trunk_port.mode = 'tagged'
                    trunk_port.save()
                    # 3.1 add virtual interface to bridge
                    virtual_interface.bridge = bridge_interface
                    virtual_interface.save()

            if access_interfaces:
                access_interfaces.update(bridge=bridge_interface, mode='access', untagged_vlan=vlan_object)

        self.log_debug(str(commands_applied))
        html_template = """ <p>
                            <a href="https://nb.rona.best/extras/scripts/vlan_create_by_device.RunCommand/">Налаштування VLAN</a>
                           </p>
                        """

        self.log_info(html_template)

#######################

        return ''.join("Client:" + "\n" + commands + "\n\n\n" + "Check params:" + "\n")
