import traceback
from dcim.models import Device, Interface
from extras.scripts import Script, ObjectVar, StringVar
from ipam.models import IPAddress, VLAN
import hashlib
from netmiko import ConnectHandler


class RunCommand(Script):
    class Meta:
        name = " Начальні налаштування"
        description = "Напряму через НТМ"
        field_order = [
                     'device',
                     'usrpasswd',
                     'inter',
                    ]

    device = ObjectVar(
        model=Device,
        label='Пристрій',
        description='Пристрий який потрібно налаштувати',
    )

    device_s = ObjectVar(
        model=Device,
        description=' Server ',
        label='Server',
        required=True
    )

    inter_s = ObjectVar(
        model=Interface,
        label='WAN port for server',
        query_params={
            'device_id': '$device_s',
                     }
    )

    usrpasswd = StringVar(
        label='Пароль',
        description='Пароль для ReadOnly юзера',
    )

    srvpasswd = StringVar(
        label='Пароль сервера'
    )

    def run(self, data, commit):
        srvpasswd = data["srvpasswd"]
        passwd_hash = 'c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec'
        if hashlib.sha512(srvpasswd.encode('UTF-8')).hexdigest() != passwd_hash:
            self.log_failure('Невірний пароль сервера')
            return passwd_hash

        host = f'{data["device"].name}'
        device = Device.objects.get(name=host)
        device_s = data["device_s"]
        srv_lb = device_s.interfaces.get(name='Loopback')
        inter_s = data['inter_s']
        cfdata = Device.objects.all().values_list('custom_field_data', flat=True)
        ranges = list(range(100, 254))
        for ids in cfdata:
            if ids['IDs']:
                ranges.remove(ids['IDs'])
        device_id = ranges[0]
        device.custom_field_data['IDs'] = device_id

        lb, lmask = (f'10.10.10.{str(device_id)}', '24')
        ip, lmask = (f'192.168.1.{str(device_id)}', '24')
        ipo = f'192.168.1.112' #Server SSTP orion
        allow = f'192.168.1.0/24,10.10.10.0/24'
        allow1 = f'192.168.1.0/24'
        allow2 = f'10.10.10.0/24'
        libre = f'192.168.1.111'
        bn = f'Bond_main'
        psw = f'{data["usrpasswd"]}'
        wan_s = f'{data["inter_s"]}'

        firewall = f'/ip firewall address-list add address=' + str(allow1) + ' list=allow-ip \n' +\
            f'/ip firewall address-list add address=' + str(allow2) + ' list=allow-ip \n' +\
            f'/ip firewall filter add action=accept chain=input comment="Allow Address List" src-address-list=allow-ip \n' +\
            f'/ip firewall filter add action=accept chain=input comment="accept_established_related" \ connection-state=established,related \n' + \
            f'/ip firewall filter add action=accept chain=forward comment="accept_established_related" \ connection-state=established,related \n' + \
            f'/ip firewall connection tracking set loose-tcp-tracking=yes \n' + \
            f'/ip firewall filter add action=jump chain=input comment="Allow_ping" jump-target=ICMP protocol=icmp \n' + \
            f'/ip firewall filter add action=jump chain=forward jump-target=ICMP protocol=icmp \n' + \
            f'/ip firewall filter add action=accept chain=ICMP icmp-options=0:0 limit=5,50:packet protocol=icmp \n' + \
            f'/ip firewall filter add action=accept chain=ICMP icmp-options=3:4 limit=5,50:packet protocol=icmp \n' + \
            f'/ip firewall filter add action=accept chain=ICMP icmp-options=3:3 limit=5,50:packet protocol=icmp \n' + \
            f'/ip firewall filter add action=accept chain=ICMP icmp-options=11:0 limit=5,50:packet protocol=icmp \n' + \
            f'/ip firewall filter add action=accept chain=ICMP icmp-options=8:0 limit=5,50:packet protocol=icmp \n' + \
            f'/ip firewall filter add action=accept chain=input protocol=udp \n' + \
            f'/ip firewall filter add action=accept chain=forward protocol=udp \n' + \
            f'/ip firewall filter add action=accept chain=input protocol=tcp \n' + \
            f'/ip firewall filter add action=accept chain=forward protocol=tcp \n' + \
            f'/ip firewall filter add action=accept chain=input protocol=ospf \n' + \
            f'/ip firewall filter add action=accept chain=forward protocol=ospf \n' + \
            f'/ip firewall filter add action=accept chain=input src-address=192.168.1.0/24 \n' +\
            f'/ip neighbor discovery set bridge-interface discover=no \n' +\
            f'/ip firewall filter add chain=output action=drop src-port=5678 protocol=udp \n'

        snmp = f'/snmp community set 0 name=' + str(host) + ' addresses=' + str(libre) + ' \n' +\
            f'/snmp set enabled=yes trap-community=' + str(host) + ' contact=user-mik location=Boston trap-target=' + str(libre) + ' \n' +\
            f'/system logging action set name="remote" remote=' + str(libre) + ' remote-port=514 bsd-syslog=no numbers=3 \n' +\
            f'/system logging add topics=critical action=remote \n' +\
            f'/system logging add topics=warning action=remote \n' +\
            f'/system logging add topics=info action=remote \n' +\
            f'/system logging add topics=error action=remote \n'

        defaults = f'/interface bridge add name=Loopback \n' +\
            f'/ip address add address={str(lb)}/{lmask} interface=Loopback \n' +\
            f'/ip route add dst-address=192.168.1.0 gateway=10.10.10.112 \n' + \
            f'/ip route add dst-address=0.0.0.0/0 gateway=10.10.10.112 \n' + \
            f'/system ntp client set primary-ntp=91.236.251.5 enabled=yes \n' +\
            f'/system ntp client set servers=91.236.251.5 enabled=yes \n' +\
            f'/ip neighbor discovery-settings set discover-interface-list=none \n' + \
            f'/ip settings set tcp-syncookies=yes \n' + \
            f'/ip service set telnet disabled=yes \n' +\
            f'/ip service set ftp disabled=yes \n' +\
            f'/ip service set www disabled=no \n' +\
            f'/ip service set ssh disabled=no \n' +\
            f'/ip service set api disabled=yes \n' +\
            f'/ip service set winbox port=10' + str(device_id) + '\n' +\
            f'/ip service set api-ssl disabled=yes \n' +\
            f'/system identity set name=' + str(host) + ' \n' +\
            f'/user disable admin \n' +\
            f'/user add name=' + str(host) + ' group=full password=m1kr0tftp address=192.168.1.0/24 \n' +\
            f'/user add name=ReadOnly group=read  password=' + str(psw) + ' address=' + str(allow) + ' \n' +\
            f'/interface vlan add name=vlan_47_{bn} vlan-id=47 interface=ether1 \n' +\
            f'/interface bridge port add bridge=Loopback interface=vlan_47_{bn} \n'

        commands = defaults + firewall + snmp

####################### End MAX #################################
        orions = [
           '/interface vlan add name=vlan_47_' + str(host) + ' interface=' + str(wan_s) + ' vlan-id=47 \n',
           ' /interface bridge port add bridge=Loopback interface=vlan_47_' + str(host) + ' \n'
           ]

        mikro1 = {
            "device_type": "mikrotik_routeros",
            "host": ipo,
            "username": "admin+ct",
            "password": srvpasswd,
        }
        try:
            with ConnectHandler(**mikro1) as net_connect:
                net_connect.send_config_set(orions, cmd_verify=True)
        except Exception:
            return traceback.format_exc()

        srv_vlan_intf = Interface.objects.create(
            name=f'vlan_47_{host}',
            type='virtual',
            mode='tagged',
            device=device_s,
            parent=inter_s
        )
        vlan47 = VLAN.objects.get_or_create(name='Vlan47', vid=47)[0]
        srv_vlan_intf.tagged_vlans.add(vlan47)
        srv_vlan_intf.bridge = srv_lb
        srv_vlan_intf.save()
        inter_s.label = f'{host}'
        inter_s.save()

        loopback, _ = Interface.objects.get_or_create(name='Loopback', type='bridge', device=device)
        lb_ip = IPAddress.objects.create(address=f'{lb}/{lmask}', assigned_object=loopback)
        ether1 = device.interfaces.get(name='ether1')
        vlan_intf = Interface.objects.create(
            name=f'vlan_47',
            type='virtual',
            mode='tagged',
            device=device,
            parent=ether1
        )
        vlan_intf.tagged_vlans.add(vlan47)
        vlan_intf.bridge = loopback
        vlan_intf.save()
        device.primary_ip4 = lb_ip
        device.save()

        output = str(commands)

        self.log_info(f'ID пристою: {str(device_id)}')

        html_template = """ <p>
                            <a href="https://nb.rona.best/extras/scripts/EoIP_mik.RunCommand/">Налаштування EoIP</a>
                           </p>
                        """

        self.log_info(html_template)

        html_template2 = """ <p>
                             <a href="https://nb.rona.best/extras/scripts/VLAN_mik.RunCommand/">Налаштування Vlan</a>
                            </p>
                         """

        self.log_info(html_template2)

        return ''.join(output)