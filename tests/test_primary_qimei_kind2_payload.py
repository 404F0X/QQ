import unittest
from unittest.mock import Mock
from qq_nt_replica.primary_qimei_kind2_payload import module_suffix_signal,populate_module_initial,tree_list,populate_module_list_later
from qq_nt_replica.primary_qimei_request import QimeiRequestState,RequestSlot
class Stages(unittest.TestCase):
    def state(self):return QimeiRequestState([RequestSlot() for _ in range(48)])
    def test_last_node_case_and_independent_minimum(self):
        self.assertEqual(module_suffix_signal(()),0)
        self.assertEqual(module_suffix_signal((b'A\\SbieDll.dll',b'Z\\x')),0)
        self.assertEqual(module_suffix_signal((b'A\\x',b'Z\\SbieDll.dll')),1)
        self.assertEqual(module_suffix_signal((b'A\\sbiedll.dll',)),0)
        for flag in (-1,0,1,0xFFFFFFFF,0x100000001):
            state=self.state();state.slots[33]=RequestSlot(4,b'old!');settings=Mock();settings.flag.return_value=flag
            populate_module_initial(b'owner',state,(b'Alpha',),settings,settings_dependencies={'token':'controlled'})
            self.assertEqual(state.slots[33].data,b'old!')
            self.assertEqual(state.slots[35],RequestSlot(1,b'Alpha'))
            settings.flag.assert_called_once_with(3,group=1,token='controlled')
        state=self.state();settings.flag.return_value=1
        populate_module_initial(b'o',state,(),settings)
        self.assertEqual(state.slots[33],RequestSlot(4,bytes(4)));self.assertEqual(state.slots[35],RequestSlot())
        for flag in (-1,0,1):
            state=self.state();settings.flag.return_value=flag
            populate_module_initial(b'o',state,(b'A\\SbieDll.dll',),settings)
            self.assertEqual(state.slots[33].tag,4 if flag>0 else 0)
    def test_list_modes_order_empty_separator_and_later_flag(self):
        self.assertEqual(tree_list((b'',b'a'),0),b'a')
        tree=(b'A\\a',b'B\\',b'C\\b')
        self.assertEqual(tree_list(tree,1),b'a##b')
        self.assertEqual(tree_list((b'A\\same',b'B\\same'),257),b'same#same')
        self.assertEqual(tree_list((b'\\tail',),1),b'\\tail')
        self.assertEqual(tree_list(tree,256),b'A\\a#B\\#C\\b')
        settings=Mock()
        for flag in (0,-1,1):
            state=self.state();settings.flag.return_value=flag
            populate_module_list_later(b'o',state,tree,settings)
            self.assertEqual(state.slots[44],RequestSlot() if flag==0 else RequestSlot(1,b'a##b'))
            self.assertTrue(all(slot==RequestSlot() for i,slot in enumerate(state.slots) if i!=44))
