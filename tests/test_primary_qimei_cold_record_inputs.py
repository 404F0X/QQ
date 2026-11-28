import unittest
from qq_nt_replica.primary_qimei_getter import QimeiGetterOwner
from qq_nt_replica.primary_device_records import sdk_fields_from_qimei_owner,sdk_field_record_values
from qq_nt_replica.primary_worker_consumer import DeviceRecord,serialize_device_records
from qq_nt_replica.primary_provider_init import _VERSION
from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
class ColdInput(unittest.TestCase):
    def test_constructor_to_config_to_actual_record_wire(self):
        owner=QimeiGetterOwner();self.assertEqual(owner.status,'UNINITIALIZED');self.assertEqual(owner.get(),b'')
        fields=sdk_fields_from_qimei_owner(owner,b'public-machine\0ignored')
        records=sdk_field_record_values(fields);self.assertEqual(records,((27,b'public-machine'),(28,b''),(89,_VERSION)))
        encoded=serialize_device_records(tuple(DeviceRecord(*r) for r in records),b'',b'')
        self.assertIn(b'\x0a\x02\x08\x1c',encoded) # actual empty key28 record, not omitted
        self.assertEqual(owner.status,'UNINITIALIZED')
    def test_warm_strings_retained_and_owning_mapping(self):
        old={0x30:b'previous-qimei',0x48:b'old-machine',0x78:b'old-version'}
        fields=sdk_fields_from_qimei_owner(QimeiGetterOwner(),b'',previous=old)
        self.assertEqual(fields[0x30],old[0x30]);self.assertEqual(fields[0x48],old[0x48]);self.assertEqual(fields[0x78],_VERSION)
        fields[0x30]=b'changed';self.assertEqual(old[0x30],b'previous-qimei')
    def test_initialized_restored_boundary_never_empty(self):
        owner=QimeiGetterOwner()
        with self.assertRaises(PrimarySemanticUnavailable):owner.initialize()
        with self.assertRaises(PrimarySemanticUnavailable):owner.restore(b'anything')
        owner._ready=1 # controlled unsupported state, not a restoration API
        with self.assertRaises(PrimarySemanticUnavailable):sdk_fields_from_qimei_owner(owner,b'machine')
