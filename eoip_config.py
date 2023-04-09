import hashlib

from dcim.models import Device, DeviceRole, Interface
from django import forms
from extras.scripts import MultiObjectVar, ObjectVar, Script, StringVar
from ipam.models import VLAN
from jinja2 import Environment, StrictUndefined
from tenancy.models import *
from utilities.exceptions import AbortScript
from utilities.helper import *


router_role = DeviceRole.objects.get(name="Router")


class RunCommand(Script):
    class Meta:
        name = "EoIP"
        description = "Create EoIP"

    device_in = ObjectVar(
        model=Device,
        label="Device in",
        required=True,
        query_params={"role_id": router_role.id},
    )
    
    device_out = ObjectVar(
        model=Device,
        label="Device out",
        required=True,
        query_params={"role_id": router_role.id},
    )
    
    device_in_password = StringVar(widget=forms.PasswordInput())
    
    device_out_password = StringVar(widget=forms.PasswordInput())

    def run(self, data, commit):
      device_in = data.get('device_in')
      device_out = data.get('device_out')
      device_in_password = data.get('device_in_password')
      device_out_password = data.get('device_out_password')
      
      lb_in = device_in.interfaces.get(name='Loopback')
      lb_out = device_out.interfaces.get(name='Loopback')
      lb_in_ip = lb_in.ip_addresses.first().address.ip
      lb_out_ip = lb_out.ip_addresses.first().address.ip
      t1 = get_timestamp()
      backup_name_in = get_backup_name(device_in.name)
      backup_name_out = get_backup_name(device_out.name)
      
      eoip_id1 = get_custom_eoip_id()
      eoip_id2 = get_custom_eoip_id(existing_id=eoip_id1)
      
      eoip_in = [f'/interface eoip add name=EoIP_orion_' + str(eoip_id1) + ' local-address=' + str(lb_in_ip) + ' remote-address=' + str(lb_out_ip) + 'tunnel-id=' + str(eoip_id1) + ' comment=connect_to_' + str(device_out.name) + '_via_loopback_' + str(t1) + '\n']
      
      eoip_out = [f'/interface eoip add name=EoIP_orion_' + str(eoip_id2) + ' local-address=' + str(lb_out_ip) + ' remote-address=' + str(lb_in_ip) + 'tunnel-id=' + str(eoip_id2) + ' comment=connect_to_' + str(device_in.name) + '_via_loopback_' + str(t1) + '\n']
      
      netmiko_ssh_connect(lb_in_ip, device_in.name, device_in_password, eoip_in)
      
      try:
          ssh_connect(device_out.name, lb_out_ip, device_out_password, backup_name_out, eoip_out)
      except socket.timeout:
          raise AbortScript("Device not reachable! Check routers from/to NB")
      except paramiko.ssh_exception.AuthenticationException:
          raise AbortScript(f"Auth failed, {mt_username}, {mt_password}")
      except paramiko.SSHException:
          raise AbortScript("Failed to run commands")
      except paramiko.ssh_exception.NoValidConnectionsError:
          raise AbortScript(f"Unable to connect to {host_ip}")
      except Exception as e:
          raise AbortScript(e)
