import hashlib

from dcim.models import Device, DeviceRole, Interface
from django import forms
from extras.scripts import ObjectVar, Script, StringVar
from ipam.models import VLAN, IPAddress
from utilities.exceptions import AbortScript
from utilities.helper import *

from configs.first_provider_conf import create_config_provider
from helper import *

router_role = DeviceRole.objects.get(name="Router")


class RunCommand(Script):
    class Meta:
        name = " Начальні налаштування"
        description = "Через Інтернет-ресурс"
        field_order = [
            "device",
            "usrpasswd",
        ]

    device = ObjectVar(
        model=Device,
        label="Пристрій",
        description="Пристрий який потрібно налаштувати",
        query_params={"role_id": router_role.id},
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
        device = data.get("device")
        psw = f'{data["usrpasswd"]}'

        device_id = get_device_custom_id()
        device.custom_field_data["IDs"] = device_id
        sipo, omask, sipd, dmask, lb, lmask = get_ip_n_mask(device_id)
        id1, id2 = get_ids(device_id)
        t1 = get_timestamp()
        backup_name = get_backup_name(srv_device.name)
        bn = f"Bond_main"

        first_conf = create_config_provider(host, device_id, psw)

        orions = [
            f"/interface eoip add name=EoIP-dckz_{id2} local-address=172.16.5.1 remote-address={sipd} tunnel-id={id2} comment=connect_to_{host}_via_DCKZ_{t1}",
            f"/interface eoip add name=EoIP-orion_{id1} local-address=172.16.5.1 remote-address={sipo} tunnel-id={id1} comment=connect_to_{host}_via_ORION_{t1}",
            f"/interface bonding add name=bond_{host} slaves=EoIP-dckz_{id2},EoIP-orion_{id1} mode=broadcast comment=connect_to_{host}_{t1}",
            f"/interface vlan add name=vlan_47_bond_{host} interface=bond_{host} vlan-id=47",
            f"/interface bridge port add bridge=Loopback interface=vlan_47_bond_{host}",
        ]

        ssh_connect(srv_device.name, ipo, srvpasswd, backup_name, orions)

        vlan47 = VLAN.objects.get_or_create(name="Vlan47", vid=47)[0]
        loopback, _ = Interface.objects.get_or_create(
            name="Loopback", type="bridge", device=device
        )
        interfaces = Interface.objects.bulk_create(
            [
                Interface(name="SSTP-orion", type="virtual", device=device),
                Interface(name="SSTP-dckz", type="virtual", device=device),
            ]
        )

        eoip_interfaces = Interface.objects.bulk_create(
            [
                Interface(name=f"EoIP-orion_{id1}", type="virtual", device=device),
                Interface(name=f"EoIP-dckz_{id2}", type="virtual", device=device),
            ]
        )

        bond_interface = Interface.objects.create(
            name=bn, type="virtual", mode="tagged", device=device
        )
        bond_interface.tagged_vlans.add(vlan47)
        bond_interface.child_interfaces.add(*eoip_interfaces)
        bond_interface.save()

        time.sleep(2)
        addresses = IPAddress.objects.bulk_create(
            [
                IPAddress(address=f"{lb}/{lmask}", assigned_object=loopback),
                IPAddress(address=f"{sipo}/{omask}", assigned_object=interfaces[0]),
                IPAddress(address=f"{sipd}/{dmask}", assigned_object=interfaces[1]),
            ]
        )

        device.primary_ip4 = addresses[0]
        vlan_intf = Interface.objects.create(
            name=f"vlan_47",
            type="virtual",
            mode="tagged",
            device=device,
            parent=bond_interface,
        )
        vlan_intf.tagged_vlans.add(vlan47)
        vlan_intf.bridge = loopback
        vlan_intf.save()
        device.save()

        srv_eoip_interfaces = Interface.objects.bulk_create(
            [
                Interface(name=f"EoIP-dckz_{host}", type="virtual", device=srv_device),
                Interface(name=f"EoIP-orion_{host}", type="virtual", device=srv_device),
            ]
        )
        srv_bond_interface = Interface.objects.create(
            name=f"bond_{host}", type="virtual", mode="tagged", device=srv_device
        )
        srv_bond_interface.tagged_vlans.add(vlan47)
        srv_bond_interface.child_interfaces.add(*srv_eoip_interfaces)
        srv_bond_interface.label = f"{host}"
        srv_bond_interface.save()
        srv_vlan_intf = Interface.objects.create(
            name=f"vlan_47_{srv_bond_interface.name}",
            type="virtual",
            mode="tagged",
            device=srv_device,
            parent=srv_bond_interface,
        )
        srv_vlan_intf.tagged_vlans.add(vlan47)
        srv_vlan_intf.bridge = srv_device.interfaces.get(name="Loopback")
        srv_vlan_intf.save()

        self.log_info(f"ID пристою: {str(device_id)}")

        html_template = """ 
        <p><a href="https://nb.rona.best/extras/scripts/vlan_create_by_device.RunCommand/">Налаштування VLAN</a></p> 
        """

        self.log_info(html_template)

        return first_conf
