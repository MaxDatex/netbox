from dcim.models import Device, Interface, Cable, DeviceRole
from extras.scripts import Script, ObjectVar, StringVar
from ipam.models import IPAddress, VLAN
import hashlib
import paramiko
from django import forms
from utilities.exceptions import AbortScript
import time
import socket
from pathlib import Path
import datetime


router_role = DeviceRole.objects.get(name="Router")
device_s = Device.objects.get(primary_ip4__address='192.168.1.112/24')
t = datetime.datetime.now()
t1 = f'{t.strftime("%Y-%m-%d_%H:%M:%S")}'


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
        query_params={
            "role_id": router_role.id
        }
    )
    #
    # device_s = ObjectVar(
    #     model=Device,
    #     description=' Server ',
    #     label='Server',
    #     required=True
    # )

    inter_s = ObjectVar(
        model=Interface,
        label='WAN port for server',
        query_params={
            'device_id': device_s.id,
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
        device = Device.objects.get(name=host)
        srv_lb = device_s.interfaces.get(name='Loopback')
        inter_s = data['inter_s']

        cfdata = Device.objects.all().values_list('custom_field_data', flat=True)
        ranges = list(range(100, 254))
        for ids in cfdata:
            if ids.get('IDs'):
                ranges.remove(ids.get('IDs'))
        device_id = ranges[0]
        device.custom_field_data['IDs'] = device_id

        lb, lmask = (f'10.10.10.{str(device_id)}', '24')
        ip, lmask = (f'192.168.1.{str(device_id)}', '24')
        ipo = f'192.168.1.112' #Server SSTP orion
        allow = f'192.168.1.0/24,10.10.10.0/24'
        allow1 = f'192.168.1.0/24'
        allow2 = f'10.10.10.0/24'
        libre = f'192.168.1.23'
        psw = f'{data["usrpasswd"]}'
        wan_s = f'{data["inter_s"]}'
        ether1 = device.interfaces.get(name='ether1')
        t1 = f'{t.strftime("%Y_%m_%d_%H_%M_%S")}'
        backup_name = device_s.name + "_" + t1 + '.backup'

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
            f'/system logging add topics=error action=remote \n/'

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
            f'/user add name=' + str(host) + ' group=full password=m1kr0tftp address=192.168.1.0/24 \n' +\
            f'/user disable admin \n' +\
            f'/user add name=ReadOnly group=read  password=' + str(psw) + ' address=' + str(allow) + ' \n' +\
            f'/interface vlan add name=vlan_47_ether1 vlan-id=47 interface=ether1 \n' +\
            f'/interface bridge port add bridge=Loopback interface=vlan_47_ether1 \n'

        commands = defaults + firewall + snmp

####################### End MAX #################################
        orions = [
           '/interface vlan add name=vlan_47_' + str(host) + ' interface=' + str(wan_s) + ' vlan-id=47 \n',
           ' /interface bridge port add bridge=Loopback interface=vlan_47_' + str(host) + ' \n'
           ]

        mt_username = 'admin+ct'
        mt_password = srvpasswd
        timeout = 10

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(str(ipo), username=mt_username, password=mt_password, timeout=timeout)
            stdin, stdout, stderr = ssh.exec_command(f'system backup save name={backup_name} dont-encrypt=yes')
            time.sleep(2)
            for mt_command in orions:
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

        Path(f'/opt/netbox/netbox/{device_s.name}_backup').mkdir(parents=True, exist_ok=True)
        sftp = ssh.open_sftp()
        sftp.get(f'/{backup_name}', f'/opt/netbox/netbox/{device_s.name}_backup/{backup_name}')
        sftp.close()

        ssh.get_transport().close()
        ssh.close()

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
        vlan_intf = Interface.objects.create(
            name=f'vlan_47_ether1',
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

        Cable.objects.create(a_terminations=[inter_s], b_terminations=[ether1])

        output = str(commands)

        self.log_info(f'ID пристою: {str(device_id)}')

        html_template = """ <p>
                            <a href="https://nb.rona.best/extras/scripts/vlan_create_by_device.RunCommand/">Налаштування VLAN</a>
                           </p>
                        """

        self.log_info(html_template)

        return ''.join(output)
