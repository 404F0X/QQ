import unittest
from types import SimpleNamespace
from unittest.mock import patch
from qq_nt_replica.primary_qimei_application_binding import derive_application_msf_path
from qq_nt_replica import primary_outer_init as outer
from qq_nt_replica.primary_qimei_request import QimeiRequestBoundary
from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
class Spaces(unittest.TestCase):
    def test_literal_internal_spaces_both_guards(self):
        for value in (r'F:\Tencent Files\Profile_1',r'C:\a  b\nt_data\msf',r'D:\A-B  C_1'):
            self.assertEqual(derive_application_msf_path(value),value+r'\nt_data\msf')
            with patch.object(outer._String,'construct',return_value='owned') as construct:
                source=SimpleNamespace(value=lambda:value.encode('ascii'))
                self.assertEqual(outer.login_nt_data_path(None,source),'owned')
                construct.assert_called_once_with(None,value.encode('ascii')+br'\nt_data')
    def test_other_domains_stay_rejected(self):
        for value in ('C:\\ leading','C:\\trailing ','C:\\a\tb','C:\\a.','C:\\汉',r'\\host\share','relative',r'C:\a\..\b'):
            with self.assertRaises(QimeiRequestBoundary):derive_application_msf_path(value)
            with patch.object(outer._String,'construct') as construct:
                with self.assertRaises(PrimarySemanticUnavailable):outer.login_nt_data_path(None,SimpleNamespace(value=lambda:value.encode('utf-8')))
                construct.assert_not_called()
