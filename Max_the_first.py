from pathlib import Path
from dcim.models import Device, Interface, DeviceRole
from extras.scripts import Script, ObjectVar, StringVar
from ipam.models import IPAddress, VLAN
import hashlib
import paramiko
import socket
import datetime
import time
from django import forms
from utilities.exceptions import AbortScript
from jinja2 import Environment, StrictUndefined


t = datetime.datetime.now()
t1 = f'{t.strftime("%Y-%m-%d_%H:%M:%S")}'
router_role = DeviceRole.objects.get(name="Router")

orions = '''/interface eoip add name=EoIP-dckz_{{ id_dckz }} local-address=172.16.5.1 remote-address={{ sipd }} tunnel-id={{ id_dckz }} comment=connect_to_{{ host }}_via_DCKZ_{{ t1 }}
/interface eoip add name=EoIP-orion_{{ id_orion }} local-address=172.16.5.1 remote-address={{ sipo }} tunnel-id={{ id_orion }} comment=connect_to_{{ host }}_via_ORION_{{ t1 }}
/interface bonding add name=bond_{{ host }} slaves=EoIP-dckz_{{ id_dckz }},EoIP-orion_{{ id_orion }} mode=broadcast comment=connect_to_{{ host }}_{{ t1 }}
/interface vlan add name=vlan_47_bond_{{ host }} interface=bond_{{ host }} vlan-id=47
/interface bridge port add bridge=Loopback interface=vlan_47_bond_{{ host }}
'''


class RunCommand(Script):
    class Meta:
        name = " Начальні налаштування"
        description = "Через Інтернет-ресурс"
        field_order = [
                     'device',
                     'usrpasswd',
                    ]

    device = ObjectVar(
        model=Device,
        label='Пристрій',
        description='Пристрий який потрібно налаштувати',
        query_params={
            "role_id": router_role.id
        }
    )

    usrpasswd = StringVar(
        label='Пароль',
        description='Пароль для ReadOnly юзера',
    )

    srvpasswd = StringVar(
        label='Пароль сервера',
        widget=forms.PasswordInput()
    )

    def run(self, data, commit):
        srvpasswd = data["srvpasswd"]
        passwd_hash = 'c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec'
        if hashlib.sha512(srvpasswd.encode('UTF-8')).hexdigest() != passwd_hash:
            raise AbortScript("Password is incorrect")

        host = f'{data["device"].name}'
        device = data.get('device')

        cfdata = Device.objects.all().values_list('custom_field_data', flat=True)
        ranges = list(range(100, 254))
        for ids in cfdata:
            print(ids['IDs'])
            if ids['IDs']:
                print(True, ids["IDs"])
                ranges.remove(ids['IDs'])
        device_id = ranges[0]
        device.custom_field_data['IDs'] = device_id

        sipo, omask = (f'172.16.2.{str(device_id)}', '24')
        sipd, dmask = (f'172.16.6.{str(device_id)}', '24')
        lb, lmask = (f'10.10.10.{str(device_id)}', '24')
        ipo = f'192.168.1.112' #Server SSTP orion
        ipd = f'192.168.1.117' #Server SSTP dckz
        allow = f'192.168.1.0/24,10.10.10.0/24'
        allow1 = f'192.168.1.0/24'
        allow2 = f'10.10.10.0/24'
        libre = f'192.168.1.111'
        id1 = f'1' + str(device_id)
        id2 = f'2' + str(device_id)
        bn = f'Bond_main'
        psw = f'{data["usrpasswd"]}'
        t1 = f'{t.strftime("%Y_%m_%d_%H_%M_%S")}'
        srv_device = Device.objects.get(primary_ip4__address=ipo + '/24')
        backup_name = srv_device.name + "_" + t1 + '.backup'

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
            f'/ip firewall filter add action=accept chain=input src-address=192.168.1.0/24 \n'

        sstp = f'/ppp profile add local-address={str(sipo)} name=SSTP-orion remote-address=172.16.2.1 comment=connect_to_IF_via_orion \n' +\
            f'/ppp secret add name=SSTP-orion' + ' password=SSTP-orion service=sstp profile=SSTP local-address=' + str(sipo) + ' remote-address=172.16.2.1' + ' comment=connect_to_IF_via_orion \n' +\
            f'/interface sstp-client add user=SSTP password=SSTP-orion connect-to=' + str(ipo) + ' profile=SSTP name=SSTP-orion' + ' comment=connect_to_IF_orion \n' +\
            f'/ppp profile add local-address=' + str(sipd) + ' name=SSTP-dckz remote-address=172.16.6.1' + ' comment=connect_to_IF_via_DCKZ \n' +\
            f'/ppp secret add name=SSTP-dckz password=SSTP-dckz service=sstp profile=SSTP-dckz local-address=' + str(sipd) + ' remote-address=172.16.6.1' + ' comment=connect_to_IF_via_DCKZ \n' +\
            f'/interface sstp-client add user=SSTP-dckz password=SSTP-dckz connect-to=' + str(ipd) + ' profile=SSTP-dckz name=SSTP-dckz' +  ' comment=connect_to_IF_viz_DCKZ \n' +\
            f'/interface sstp-client enable SSTP-orion \n' +\
            f'/interface sstp-client enable SSTP-dckz \n'

        snmp = f'/snmp community set 0 name=' + str(host) + ' addresses=' + str(libre) + ' \n' +\
            f'/snmp set enabled=yes trap-community=' + str(host) + ' contact=user-mik location=Boston trap-target=' + str(libre) + ' \n' +\
            f'/system logging action set name="remote" remote=' + str(libre) + ' remote-port=514 bsd-syslog=no numbers=3 \n' +\
            f'/system logging add topics=critical action=remote \n' +\
            f'/system logging add topics=warning action=remote \n' +\
            f'/system logging add topics=info action=remote \n' +\
            f'/system logging add topics=error action=remote \n/'

############### EoIP + bond + Vlan ###################
        eoip = f'/interface eoip add name=EoIP_orion_' + str(id1) + ' local-address=' + str(sipo) + ' remote-address=172.16.2.1 tunnel-id=' + str(id1) + ' comment=connect_to_IF_via_orion_' + str(t1) + '\n' + \
            f'/interface eoip add name=EoIP_dckz_' + str(id2) + ' local-address=' + str(sipd) + ' remote-address=172.16.5.1 tunnel-id=' + str(id2) + ' comment=connect_to_IF_viz_DCKZ_' + str(t1) + '\n' + \
            f'/interface bonding add name=' + str(bn) + ' slaves=EoIP_orion_' + str(id1) + ',EoIP_dckz_' + str(id2) + ' mode=broadcast comment=connect_to_IF_via_DCKZ_' + str(t1) + '\n' + \
            f'/interface vlan add name=vlan_47_{bn} vlan-id=47 interface={bn} \n' +\
            f'/interface bridge port add bridge=Loopback interface=vlan_47_{bn} \n'
#####################################################

        defaults = f'ip dhcp-client add interface=ether1 add-default-route=yes disabled=no \n' +\
            f'/interface bridge add name=Loopback \n' +\
            f'/ip address add address={str(lb)}/{lmask} interface=Loopback \n' +\
            f'/ip route add dst-address=172.16.5.0/24 gateway=172.16.6.1 comment=create_' + str(t1) + '\n' + \
            f'/ip route add dst-address=192.168.1.111/32 gateway=10.10.10.112 comment=create_' + str(t1) + '\n' + \
            f'/ip route add dst-address=192.168.1.123/32 gateway=10.10.10.112 comment=create_' + str(t1) + '\n' + \
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
            f'/user add name=' + str(host) + ' group=full password=m1kr0tftp address=192.168.1.0/24 \n' +\
            f'/user disable admin \n' +\
            f'/user add name=ReadOnly group=read  password=' + str(psw) + ' address=' + str(allow) + ' \n'

        first_conf = defaults + firewall + sstp + eoip + snmp

##########################################################

        jenv = Environment(undefined=StrictUndefined, trim_blocks=True)
        jtemplate = jenv.from_string(orions)

        data_to_render = {
            "id_orion": id1,
            "id_dckz": id2,
            "host": host,
            "t1": t1,
            "sipd": sipd,
            "sipo": sipo
        }

        commands = jtemplate.render(data_to_render)

        mt_username = 'admin+ct'
        mt_password = srvpasswd
        timeout = 10

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(str(ipo), username=mt_username, password=mt_password, timeout=timeout)
            stdin, stdout, stderr = ssh.exec_command(f'system backup save name={backup_name} dont-encrypt=yes')
            time.sleep(2)
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

        Path(f'/opt/netbox/netbox/{srv_device.name}_backup').mkdir(parents=True, exist_ok=True)
        sftp = ssh.open_sftp()
        sftp.get(f'/{backup_name}', f'/opt/netbox/netbox/{srv_device.name}_backup/{backup_name}')
        sftp.close()

        ssh.get_transport().close()
        ssh.close()


###################### Start MAX ####################################

        vlan47 = VLAN.objects.get_or_create(name='Vlan47', vid=47)[0]
        loopback, _ = Interface.objects.get_or_create(name='Loopback', type='bridge', device=device)
        interfaces = Interface.objects.bulk_create([
                Interface(name='SSTP-orion', type='virtual', device=device),
                Interface(name='SSTP-dckz', type='virtual', device=device),
            ])

        eoip_interfaces = Interface.objects.bulk_create([
            Interface(name=f'EoIP-orion_{id1}', type='virtual', device=device),
            Interface(name=f'EoIP-dckz_{id2}', type='virtual', device=device)
        ])

        bond_interface = Interface.objects.create(name=bn, type='virtual', mode='tagged', device=device)
        bond_interface.tagged_vlans.add(vlan47)
        bond_interface.child_interfaces.add(*eoip_interfaces)
        bond_interface.save()

        time.sleep(2)
        addresses = IPAddress.objects.bulk_create([
                IPAddress(address=f'{lb}/{lmask}', assigned_object=loopback),
                IPAddress(address=f'{sipo}/{omask}', assigned_object=interfaces[0]),
                IPAddress(address=f'{sipd}/{dmask}', assigned_object=interfaces[1]),
            ])

        device.primary_ip4 = addresses[0]
        vlan_intf = Interface.objects.create(
            name=f'vlan_47',
            type='virtual',
            mode='tagged',
            device=device,
            parent=bond_interface
        )
        vlan_intf.tagged_vlans.add(vlan47)
        vlan_intf.bridge = loopback
        vlan_intf.save()
        device.save()
####################### End MAX #####################################

        srv_eoip_interfaces = Interface.objects.bulk_create([
            Interface(name=f'EoIP-dckz_{host}', type='virtual', device=srv_device),
            Interface(name=f'EoIP-orion_{host}', type='virtual', device=srv_device)
        ])
        srv_bond_interface = Interface.objects.create(name=f'bond_{host}', type='virtual', mode='tagged', device=srv_device)
        srv_bond_interface.tagged_vlans.add(vlan47)
        srv_bond_interface.child_interfaces.add(*srv_eoip_interfaces)
        srv_bond_interface.label = f'{host}'
        srv_bond_interface.save()
        srv_vlan_intf = Interface.objects.create(
            name=f'vlan_47_{srv_bond_interface.name}',
            type='virtual',
            mode='tagged',
            device=srv_device,
            parent=srv_bond_interface
        )
        srv_vlan_intf.tagged_vlans.add(vlan47)
        srv_vlan_intf.bridge = srv_device.interfaces.get(name='Loopback')
        srv_vlan_intf.save()

        self.log_info(f'ID пристою: {str(device_id)}')

        html_template = """ <p>
                                    <a href="https://nb.rona.best/extras/scripts/vlan_create_by_device.RunCommand/">Налаштування VLAN</a>
                                   </p>
                                """

        self.log_info(html_template)

        return first_conf
