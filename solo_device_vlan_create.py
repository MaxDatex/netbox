import hashlib

from dcim.models import Device, DeviceRole, Interface
from django import forms
from extras.scripts import MultiObjectVar, ObjectVar, Script, StringVar
from ipam.models import VLAN
from jinja2 import Environment, StrictUndefined
from tenancy.models import *
from utilities.exceptions import AbortScript
from utilities.helper import *

from helper import *

COMMANDS_TEMPLATE = """/interface bridge add name=Br_{{ vid }} comment=from_NB_{{ timestamp }}
{% for trunk_port in trunks %}
/interface vlan add interface={{ trunk_port }} name=vlan_{{ vid }}_{{ trunk_port }} vlan-id={{ vid }} disable=no comment=from_NB_{{ timestamp }}
/interface bridge port add bridge=Br_{{ vid }} interface=vlan_{{ vid }}_{{ trunk_port }} comment=from_NB_{{ timestamp }}
{% endfor %}
{% for access_port in access %}
/interface bridge port add bridge=Br_{{ vid }} interface={{ access_port }} comment=from_NB_{{ timestamp }}
{% endfor %}
"""

router_role = DeviceRole.objects.get(name="Router")


class RunCommand(Script):
    class Meta:
        name = "VLAN"
        description = "Set VLAN"

    device = ObjectVar(
        model=Device,
        description=" ТЕСТ ",
        label="Name Dev",
        required=True,
        query_params={"role_id": router_role.id},
    )

    srvpasswd = StringVar(label="Пароль сервера", widget=forms.PasswordInput())

    iin = MultiObjectVar(
        model=Interface,
        label="trunk ports VLAN",
        query_params={
            "device_id": "$device",
            "mode__n": "access",
        },
    )

    iout = MultiObjectVar(
        required=False,
        model=Interface,
        label="Access ports VLAN",
        query_params={
            "device_id": "$device",
            "mode__n": "access",
            "interface_id__n": "$iin",
        },
    )

    vlan_id = ObjectVar(model=VLAN, label="VLAN (ID)", required=True)

    def run(self, data, commit):
        srvpasswd = data["srvpasswd"]
        if hashlib.sha512(srvpasswd.encode("UTF-8")).hexdigest() != passwd_hash:
            raise AbortScript("Password is incorrect")

        trunk_interfaces = data.get("iin")
        access_interfaces = data.get("iout")
        for acc_port in access_interfaces:
            if acc_port in trunk_interfaces:
                raise AbortScript(
                    f"Access port {acc_port} have intersection with trunk ports"
                )

        host = f'{data["device"].name}'
        host_ip = data["device"].primary_ip.address.ip
        vid = f'{data["vlan_id"].vid}'
        vlan_object = data.get("vlan_id")
        backup_name = get_backup_name(host)

        data_to_render = {
            "vid": vid,
            "trunks": [i.name for i in trunk_interfaces],
            "access": [i.name for i in access_interfaces],
            "timestamp": get_timestamp(),
        }

        jenv = Environment(undefined=StrictUndefined, trim_blocks=True)
        jtemplate = jenv.from_string(COMMANDS_TEMPLATE)

        commands = jtemplate.render(data_to_render)

        ssh_connect(host, host_ip, srvpasswd, backup_name, commands.splitlines())

        if commit:
            bridge_name = f"Br_{vid}"
            device = data.get("device")

            # 1. create bridge interface
            bridge_interface, _ = device.interfaces.get_or_create(
                type="bridge", name=bridge_name
            )
            # 2.1 for all trunk ports create virtual inteface like vlan_{vid}_{interface}
            if trunk_interfaces:
                for trunk_port in trunk_interfaces:
                    vint_name = f"vlan_{vid}_{trunk_port.name}"
                    # 2.2 set parent for virtual interface as trunk_port
                    virtual_interface, _ = device.interfaces.get_or_create(
                        type="virtual", name=vint_name, parent=trunk_port
                    )
                    # 2.3 set untagged vlan
                    virtual_interface.untagged_vlan = vlan_object
                    virtual_interface.mode = "access"
                    # 2.4 set tagged vlan to trunk port
                    trunk_port.tagged_vlans.add(vlan_object)
                    trunk_port.mode = "tagged"
                    trunk_port.save()
                    # 3.1 add virtual interface to bridge
                    virtual_interface.bridge = bridge_interface
                    virtual_interface.save()

            if access_interfaces:
                access_interfaces.update(
                    bridge=bridge_interface, mode="access", untagged_vlan=vlan_object
                )

        html_template = """ 
        <p><a href="https://nb.rona.best/extras/scripts/vlan_create_by_device.RunCommand/">Налаштування VLAN</a></p>
        """

        self.log_info(html_template)

        return "".join("Client:" + "\n" + commands + "\n\n\n" + "Check params:" + "\n")
