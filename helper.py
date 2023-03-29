import datetime
from dcim.models import Device, DeviceRole

ipo = f'192.168.1.112' #Server SSTP orion
ipd = f'192.168.1.117' #Server SSTP dckz
allow = f'192.168.1.0/24,10.10.10.0/24'
allow1 = f'192.168.1.0/24'
allow2 = f'10.10.10.0/24'
libre = f'192.168.1.111'
passwd_hash = 'c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec'

srv_device = Device.objects.get(primary_ip4__address=ipo + '/24')
router_role = DeviceRole.objects.get(name="Router")


def get_ip_n_mask(device_id):
    sipo, omask = (f'172.16.2.{str(device_id)}', '24')
    sipd, dmask = (f'172.16.6.{str(device_id)}', '24')
    lb, lmask = (f'10.10.10.{str(device_id)}', '24')
    return sipo, omask, sipd, dmask, lb, lmask


def get_ids(device_id):
    return f'1' + str(device_id), f'2' + str(device_id)


def get_timestamp():
    t = datetime.datetime.now()
    return f'{t.strftime("%Y-%m-%d_%H:%M:%S")}'


def get_backup_name(hostname):
    t = get_timestamp()
    return hostname + "_" + t + '.backup'


def get_device_custom_id():
    cfdata = Device.objects.all().values_list('custom_field_data', flat=True)
    ranges = list(range(100, 254))
    for ids in cfdata:
        print(ids['IDs'])
        if ids['IDs']:
            print(True, ids["IDs"])
            ranges.remove(ids['IDs'])
    device_id = ranges[0]
    return device_id
