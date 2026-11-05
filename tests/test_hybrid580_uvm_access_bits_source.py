from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
BRIDGE = (ROOT / 'src/hybrid580_uvm_callback_bridge.c').read_text()


def exported_function(name):
    match = re.search(
        rf'NV_STATUS\s+{re.escape(name)}\s*\(.*?EXPORT_SYMBOL\({re.escape(name)}\);',
        BRIDGE, re.DOTALL)
    if match is None:
        raise AssertionError(f'missing exported definition for {name}')
    return match.group(0)


class Hybrid580UvmAccessBitsSourceContract(unittest.TestCase):
    def test_r595_access_bits_exports_use_gpu_owner_routing(self):
        apis = {
            'nvUvmInterfaceAccessBitsBufAlloc': 'hybrid580_open_access_bits_alloc',
            'nvUvmInterfaceAccessBitsBufFree': 'hybrid580_open_access_bits_free',
            'nvUvmInterfaceAccessBitsDump': 'hybrid580_open_access_bits_dump',
        }
        for api, open_callback in apis.items():
            with self.subTest(api=api):
                definition = exported_function(api)
                self.assertIn('hybrid580_uvm_device_call(', definition)
                self.assertIn(open_callback, definition)
                self.assertIn('hybrid580_uvm_access_bits_not_supported', definition)
                self.assertRegex(definition, r'EXPORT_SYMBOL\(' + re.escape(api) + r'\);')

    def test_access_bits_open_callbacks_preserve_native_r595_payload(self):
        callbacks = {
            'hybrid580_open_access_bits_alloc':
                'hybrid580_open_nvUvmInterfaceAccessBitsBufAlloc',
            'hybrid580_open_access_bits_free':
                'hybrid580_open_nvUvmInterfaceAccessBitsBufFree',
            'hybrid580_open_access_bits_dump':
                'hybrid580_open_nvUvmInterfaceAccessBitsDump',
        }
        for callback, private_api in callbacks.items():
            with self.subTest(callback=callback):
                self.assertIn(f'{callback}(', BRIDGE)
                self.assertIn(private_api, BRIDGE)
                self.assertIn('(uvmGpuDeviceHandle)native_device', BRIDGE)
        self.assertIn('return NV_ERR_NOT_SUPPORTED;', BRIDGE)
        self.assertNotRegex(BRIDGE, r'hybrid580_legacy_nvUvmInterfaceAccessBits')

    def test_access_bits_dump_rejects_unknown_modes_before_provider_dispatch(self):
        definition = exported_function('nvUvmInterfaceAccessBitsDump')
        for mode in ('AGGREGATE', 'DIFF', 'CURRENT'):
            self.assertIn(f'UVM_ACCESS_BITS_DUMP_MODE_{mode}', definition)
        validation = definition.index('switch')
        dispatch = definition.index('hybrid580_uvm_device_call')
        self.assertLess(validation, dispatch)
        self.assertIn('default:', definition)
        self.assertIn('NV_ERR_INVALID_ARGUMENT', definition)


if __name__ == '__main__':
    unittest.main()
