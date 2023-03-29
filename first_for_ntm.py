import hashlib

from dcim.models import Cable, Device, DeviceRole, Interface
from django import forms
from extras.scripts import ObjectVar, Script, StringVar
from ipam.models import VLAN, IPAddress
from utilities.exceptions import AbortScript
from utilities.helper import *

from configs.first_ntm_conf import create_config
from helper import *

router_role = DeviceRole.objects.get(name="Router")


class RunCommand(Script):
    class Meta:
        name = " Начальні налаштування"
        description = "Напряму через НТМ"
        field_order = [
            "device",
            "usrpasswd",
            "inter",
        ]

    device = ObjectVar(
        model=Device,
        label="Пристрій",
        description="Пристрий який потрібно налаштувати",
        query_params={"role_id": router_role.id},
    )

    inter_s = ObjectVar(
        model=Interface,
        label="WAN port for server",
        query_params={
            "device_id": srv_device.id,
        },
    )

    usrpasswd = StringVar(
        label="Пароль",
        description="Пароль для ReadOnly юзера",
    )

    srvpasswd = StringVar(label="Пароль сервера", widget=forms.PasswordInput())

    def run(self, data, commit):
        srvpasswd = data["srvpasswd"]
        if hashlib.sha512(srvpasswd.encode("UTF-8")).hexdigest() != passwd_hash:
            raise AbortScript("Password is incorrect")

        host = f'{data["device"].name}'
        device = data["device"]
        inter_s = data["inter_s"]
        psw = f'{data["usrpasswd"]}'
        wan_s = f'{data["inter_s"]}'
        device_id = get_device_custom_id()
        device.custom_field_data["IDs"] = device_id
        _, _, _, _, lb, lmask = get_ip_n_mask(device_id)
        backup_name = get_backup_name(srv_device.name)
        ether1 = device.interfaces.get(name="ether1")

        orions = [
            "/interface vlan add name=vlan_47_"
            + str(host)
            + " interface="
            + str(wan_s)
            + " vlan-id=47 \n",
            " /interface bridge port add bridge=Loopback interface=vlan_47_"
            + str(host)
            + " \n",
        ]

        ssh_connect(srv_device.name, ipo, srvpasswd, backup_name, orions)

        srv_vlan_intf = Interface.objects.create(
            name=f"vlan_47_{host}",
            type="virtual",
            mode="tagged",
            device=srv_device,
            parent=inter_s,
        )
        vlan47 = VLAN.objects.get_or_create(name="Vlan47", vid=47)[0]
        srv_vlan_intf.tagged_vlans.add(vlan47)
        srv_vlan_intf.bridge = srv_lb
        srv_vlan_intf.save()
        inter_s.label = f"{host}"
        inter_s.save()

        loopback, _ = Interface.objects.get_or_create(
            name="Loopback", type="bridge", device=device
        )
        lb_ip = IPAddress.objects.create(
            address=f"{lb}/{lmask}", assigned_object=loopback
        )
        vlan_intf = Interface.objects.create(
            name=f"vlan_47_ether1",
            type="virtual",
            mode="tagged",
            device=device,
            parent=ether1,
        )
        vlan_intf.tagged_vlans.add(vlan47)
        vlan_intf.bridge = loopback
        vlan_intf.save()
        device.primary_ip4 = lb_ip
        device.save()

        Cable.objects.create(a_terminations=[inter_s], b_terminations=[ether1])

        self.log_info(f"ID пристою: {str(device_id)}")

        html_template = """
        <p><a href="https://nb.rona.best/extras/scripts/vlan_create_by_device.RunCommand/">Налаштування VLAN</a></p>
        """

        self.log_info(html_template)

        output = create_config(host, device_id, psw)
        return "".join(output)
