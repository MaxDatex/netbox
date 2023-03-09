import datetime
import socket
import time
import traceback

import paramiko
from dcim.models import Device, Interface
from extras.scripts import Script, ObjectVar, MultiObjectVar
from ipam.models import VLAN
from jinja2 import Environment, StrictUndefined
from netmiko import ConnectHandler
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

ct1 = '''/interface print where name=Br_{{ vid }}'''
ct2 = '''/interface bridge port print where bridge=Br_{{ vid }}'''
ct3 = '''/interface bridge port print where bridge=Br_{{ vid }}'''


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
        server_ip = '192.168.1.112/24'
        host_ip = Device.objects.get(name=host).primary_ip.address.ip
        vid = f'{data["vlan_id"].vid}'
        vlan_object = data.get('vlan_id')
        trunk_interfaces = data.get('iin')
        access_interfaces = data.get('iout')

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

        jenv1 = Environment(undefined=StrictUndefined, trim_blocks=True)
        jtemplate1 = jenv1.from_string(ct1)

        temp1 = jtemplate1.render(data_to_render)

#############
        jenv2 = Environment(undefined=StrictUndefined, trim_blocks=True)
        jtemplate2 = jenv2.from_string(ct2)

        temp2 = jtemplate2.render(data_to_render)

        mt_username = host
        mt_password = "m1kr0tftp"
        timeout = 10

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        commands_applied = True

        # Client
        try:
            ssh.connect(str(host_ip), username=mt_username, password=mt_password, timeout=timeout)

        except socket.timeout:
            self.log_failure(traceback.format_exc())
            with open("error.log", "a") as f:
                f.write(t1 + " " + host + " Timeout connecting to the device.\n")
            commands_applied = False
            return traceback.format_exc()

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

        # Server
        mik1 = {
            "device_type": "mikrotik_routeros",
            "ip": server_ip[:-3],
            "username": "admin+ct",
            "password": "admin",
               }

        try:
            with ConnectHandler(**mik1) as net_connect:
                self.log_success('Connected to server successfully')

                # Server
                net_connect.send_command(f'/interface bridge add name=Br_{vid}')
                time.sleep(2)
                net_connect.send_command(f'/interface vlan add name=vlan_{vid}_ether1 interface=ether1 vlan-id={vid}')
                time.sleep(2)
                net_connect.send_command(f'/interface bridge port add bridge=Br_{vid} interface=vlan_{vid}_ether1')
                time.sleep(2)

                # Налаштування відбуваться на мікроті клієнта, тому транковий інтерфейс завжди bond
                net_connect.send_command(f'/interface vlan add interface=bond_{host} name=vlan_{ vid }_bond_{host} vlan-id={ vid } disable=no')
                time.sleep(2)
                net_connect.send_command(f'/interface bridge port add bridge=Br_{ vid } interface=vlan_{ vid }_bond_{ host }')
                time.sleep(2)

                for c1 in temp1.splitlines():
                    net_connect.send_command(c1)
                    time.sleep(2)
                for c2 in temp2.splitlines():
                    net_connect.send_command(c2)
                    time.sleep(2)

            net_connect.disconnect()

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

        except Exception:
            commands_applied = False
            self.log_failure(traceback.format_exc())
            return traceback.format_exc()

#################################################################

        # create NetBox objects if commands applied
        if commands_applied and commit:

            bridge_name = f'Br_{vid}'
            device = data.get('device')

            server = Device.objects.get(primary_ip4__address=server_ip)
            ether1 = server.interfaces.get(name='ether1')
            bond = server.interfaces.get(name=f'bond_{host}')
            server_bridge, _ = server.interfaces.get_or_create(type='bridge', name=bridge_name)
            server_vlan, _ = VLAN.objects.get_or_create(name=f'vlan{vid}', vid=int(vid))
            in_int = Interface.objects.create(
                name=f'vlan_{vid}_ether1',
                type='virtual', mode='tagged',
                device=server,
                bridge=server_bridge,
                parent=ether1
            )
            in_int.tagged_vlans.add(server_vlan)
            in_int.save()
            out_int = Interface.objects.create(
                name=f'vlan_{vid}_bond_{host}',
                type='virtual',
                mode='tagged',
                device=server,
                bridge=server_bridge,
                parent=bond
            )
            out_int.tagged_vlans.add(server_vlan)
            out_int.save()

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

#######################

        return ''.join("Client:" + "\n" + commands + "\n\n\n" + "Check params:" + "\n")
