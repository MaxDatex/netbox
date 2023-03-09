from dcim.models import Device
from extras.scripts import Script, IntegerVar


class Test(Script):
    class Meta:
        name = 'test'

    ids = IntegerVar()

    def as_form(self, data=None, files=None, initial=None):
        if data is None:  # initial form GET request /extras/scripts/Myscript.Myscript/?device=666
            cfdata = Device.objects.all().values_list('custom_field_data', flat=True)
            # taken = Device.objects.get(id=device).custom_field_data['IDs']
            # taken = []
            ranges = list(range(100, 254))
            for ids in cfdata:
                if ids['IDs']:
                    # taken.append(ids['IDs'])
                    ranges.remove(int(ids['IDs']))
            initial['ids'] = ranges[0]
            # other vars ...
        form = super().as_form(data, files, initial)
        return form

    def run(self, data, commit):
        return
