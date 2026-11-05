# SPDX-License-Identifier: MIT
"""Source contract for the BDF-routed frontend GPU-file slice."""
from pathlib import Path
import importlib.util
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('hybrid_frontend_builder', ROOT / 'tools/build_hybrid_frontend.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class HybridFrontendGpuSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / 'src/hybrid_frontend.c').read_text()
        cls.uvm_bridge = (ROOT / 'src/hybrid580_uvm_callback_bridge.c').read_text()
        cls.uvm_device_route = (ROOT / 'src/hybrid580_uvm_device_route.h').read_text()
        cls.uvm_address_space_route = (ROOT / 'src/hybrid580_uvm_address_space_route.h').read_text()
        cls.uvm_pma_route = (ROOT / 'src/hybrid580_uvm_pma_route.h').read_text()
        cls.uvm_external_mapping_route = (
            ROOT / 'src/hybrid580_uvm_external_mapping_route.h').read_text()
        cls.uvm_info_registry = (
            ROOT / 'src/hybrid580_uvm_info_registry.h').read_text()

    def test_builder_defaults_use_current_r595_r580_abi_backends(self):
        self.assertEqual(
            builder.OPEN,
            ROOT / 'build/experiments/r595-r580-open-fullbuild-v3-20261023/source')
        self.assertEqual(
            builder.LEGACY,
            ROOT / 'build/experiments/r580-private-proprietary-build-v2-20261023/nvidia-580.178.04')

    def test_backend_import_contract_includes_gpu_id_route_for_both_backends(self):
        expected = builder.expected_backend_imports()
        self.assertIn('hybrid580_open_control_session_gpu_id_info_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_gpu_id_info_v1', expected)
        self.assertIn('hybrid580_open_control_session_attached_ids_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_attached_ids_v1', expected)
        self.assertIn('hybrid580_open_control_session_probed_ids_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_probed_ids_v1', expected)
        self.assertIn('hybrid580_open_control_session_device_ids_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_device_ids_v1', expected)
        self.assertIn('hybrid580_open_control_session_device_alloc_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_device_alloc_v1', expected)
        self.assertIn('hybrid580_open_control_session_device_free_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_device_free_v1', expected)
        self.assertIn('hybrid580_open_control_session_memory_alloc_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_memory_alloc_v1', expected)
        self.assertIn('hybrid580_open_control_session_object_free_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_object_free_v1', expected)
        self.assertIn('hybrid580_open_control_session_vaspace_alloc_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_vaspace_alloc_v1', expected)
        self.assertIn('hybrid580_open_control_session_channel_group_alloc_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_channel_group_alloc_v1', expected)
        self.assertIn('hybrid580_open_control_session_context_share_alloc_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_context_share_alloc_v1', expected)
        self.assertIn('hybrid580_open_control_session_channel_alloc_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_channel_alloc_v1', expected)
        self.assertIn('hybrid580_open_control_session_engine_alloc_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_engine_alloc_v1', expected)
        self.assertIn(
            'extern __typeof__(hybrid580_open_control_session_engine_alloc_v1)\n'
            '    hybrid580_legacy_control_session_engine_alloc_v1;',
            self.source)
        self.assertIn('hybrid580_open_control_session_subdevice_alloc_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_subdevice_alloc_v1', expected)
        self.assertIn('hybrid580_open_control_session_gr_tpc_mask_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_gr_tpc_mask_v1', expected)
        self.assertIn('hybrid580_open_control_session_binapi_alloc_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_binapi_alloc_v1', expected)
        self.assertIn('hybrid580_open_control_session_rusd_alloc_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_rusd_alloc_v1', expected)
        self.assertIn('hybrid580_open_control_session_usermode_alloc_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_usermode_alloc_v1', expected)
        self.assertIn('hybrid580_open_control_session_map_memory_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_map_memory_v1', expected)
        self.assertIn('hybrid580_open_control_session_unmap_memory_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_unmap_memory_v1', expected)
        self.assertIn('hybrid580_open_control_session_update_device_mapping_info_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_update_device_mapping_info_v1', expected)
        self.assertIn('hybrid580_open_control_session_sys_params_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_sys_params_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_p2p_alloc_v1', expected)
        self.assertNotIn('hybrid580_open_control_session_p2p_alloc_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_p2p_register_va_space_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_p2p_unregister_va_space_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_p2p_register_vidmem_v1', expected)
        self.assertIn('hybrid580_legacy_control_session_p2p_unregister_vidmem_v1', expected)
        self.assertNotIn('hybrid580_open_control_session_p2p_register_va_space_v1', expected)
        self.assertNotIn('hybrid580_open_control_session_p2p_register_vidmem_v1', expected)
        for backend in ('open', 'legacy'):
            for api in ('recovery_begin_v1', 'recovery_recover_v1',
                        'recovery_end_v1', 'channels_suspend_v1',
                        'channels_resume_v1'):
                self.assertIn(f'hybrid580_{backend}_pm_{api}', expected)
        self.assertIn('hybrid580_open_pm_shared_uvm_suspend_v1', expected)
        self.assertIn('hybrid580_open_pm_shared_uvm_resume_v1', expected)
        self.assertNotIn('hybrid580_legacy_pm_shared_uvm_suspend_v1', expected)
        self.assertNotIn('hybrid580_legacy_pm_shared_uvm_resume_v1', expected)
        self.assertIn('hybrid580_open_gpu_session_register_control_v1', expected)
        self.assertIn('hybrid580_legacy_gpu_session_register_control_v1', expected)
        self.assertEqual(len(expected), 233)
        for api in builder.R595_OPEN_ONLY_UVM_APIS:
            self.assertIn('hybrid580_open_' + api, expected)
            self.assertNotIn('hybrid580_legacy_' + api, expected)
        self.assertIn('hybrid580_open_nvUvmInterfaceRegisterUvmEvents', expected)
        self.assertIn('hybrid580_open_nvUvmInterfaceDeRegisterUvmEvents', expected)
        self.assertIn('hybrid580_legacy_nvUvmInterfaceRegisterUvmCallbacks', expected)
        self.assertIn('hybrid580_legacy_nvUvmInterfaceDeRegisterUvmOps', expected)
        self.assertIn('NV_STATUS nvUvmInterfaceRegisterUvmEvents(', self.uvm_bridge)
        self.assertIn('EXPORT_SYMBOL(nvUvmInterfaceRegisterUvmEvents)', self.uvm_bridge)
        self.assertIn('NV_STATUS hybrid580_legacy_nvUvmInterfaceRegisterUvmCallbacks(',
                      self.uvm_bridge)
        self.assertIn('hybrid580_uvm_event_compat_from_linux(', self.uvm_bridge)
        for backend in ('open', 'legacy'):
            self.assertIn(f'hybrid580_{backend}_nvUvmInterfaceSessionCreate', expected)
            self.assertIn(f'hybrid580_{backend}_nvUvmInterfaceSessionDestroy', expected)
            self.assertIn(f'hybrid580_{backend}_nvUvmInterfaceRegisterGpu', expected)
            self.assertIn(f'hybrid580_{backend}_nvUvmInterfaceUnregisterGpu', expected)
            self.assertIn(f'hybrid580_{backend}_nvUvmInterfaceGetGpuInfo', expected)
            self.assertIn(f'hybrid580_{backend}_nvUvmInterfaceDeviceCreate', expected)
            self.assertIn(f'hybrid580_{backend}_nvUvmInterfaceDeviceDestroy', expected)
            for api in ('GetFbInfo', 'QueryCaps', 'QueryCopyEnginesCaps',
                        'GetEccInfo', 'GetNvlinkInfo', 'GetP2PCaps',
                        'P2pObjectCreate', 'P2pObjectDestroy', 'AddressSpaceCreate',
                        'GetPmaObject', 'PmaRegisterEvictionCallbacks',
                        'PmaUnregisterEvictionCallbacks', 'PmaAllocPages',
                        'PmaPinPages', 'PmaFreePages',
                        'DupAddressSpace', 'AddressSpaceDestroy', 'SetPageDirectory',
                        'DupAllocation',
                        'UnsetPageDirectory', 'OwnPageFaultIntr',
                        'ServiceDeviceInterruptsRM', 'MemoryAllocFB',
                        'MemoryAllocSys', 'MemoryFree', 'MemoryCpuMap',
                        'MemoryCpuUnMap', 'DupMemory', 'FreeDupedHandle',
                        'TsgAllocate', 'TsgDestroy',
                        'ChannelAllocate', 'ChannelDestroy',
                        'RetainChannel', 'BindChannelResources',
                        'ReleaseChannel', 'StopChannel',
                        'GetChannelResourcePtes'):
                self.assertIn(f'hybrid580_{backend}_nvUvmInterface{api}', expected)

    def test_uvm_session_uses_distinct_child_handles_and_one_logical_identity(self):
        self.assertIn('NV_STATUS nvUvmInterfaceSessionCreate(', self.uvm_bridge)
        self.assertIn('NV_STATUS nvUvmInterfaceSessionDestroy(', self.uvm_bridge)
        self.assertIn('hybrid580_open_nvUvmInterfaceSessionCreate', self.uvm_bridge)
        self.assertIn('hybrid580_legacy_nvUvmInterfaceSessionCreate', self.uvm_bridge)
        self.assertIn('hybrid580_uvm_session_pair_publish_identity', self.uvm_bridge)
        self.assertIn('platformInfo', self.uvm_bridge)

    def test_uvm_session_create_clears_output_before_validating_platform_output(self):
        create = self.uvm_bridge.split('NV_STATUS nvUvmInterfaceSessionCreate(', 1)[1]
        create = create.split('EXPORT_SYMBOL(nvUvmInterfaceSessionCreate);', 1)[0]
        self.assertIn('if (session == NULL)', create)
        self.assertIn('if (platformInfo == NULL)', create)
        self.assertLess(create.index('*session = NULL;'),
                        create.index('if (platformInfo == NULL)'))

    def test_uvm_gpu_registration_persists_uuid_provider_and_balances_references(self):
        self.assertIn('NV_STATUS nvUvmInterfaceRegisterGpu(', self.uvm_bridge)
        self.assertIn('void nvUvmInterfaceUnregisterGpu(', self.uvm_bridge)
        self.assertIn('hybrid580_open_nvUvmInterfaceRegisterGpu', self.uvm_bridge)
        self.assertIn('hybrid580_legacy_nvUvmInterfaceRegisterGpu', self.uvm_bridge)
        self.assertIn('hybrid580_uvm_gpu_route_register', self.uvm_bridge)
        self.assertIn('hybrid580_uvm_gpu_route_unregister', self.uvm_bridge)
        register = self.uvm_bridge.split('NV_STATUS nvUvmInterfaceRegisterGpu(', 1)[1]
        register = register.split('EXPORT_SYMBOL(nvUvmInterfaceRegisterGpu);', 1)[0]
        self.assertIn('if (gpuInfo == NULL)', register)
        self.assertIn('memset(gpuInfo, 0, sizeof(*gpuInfo));', register)
        self.assertLess(register.index('memset(gpuInfo, 0, sizeof(*gpuInfo));'),
                        register.index('if (gpuUuid == NULL)'))
        unregister = self.uvm_bridge.split('void nvUvmInterfaceUnregisterGpu(', 1)[1]
        unregister = unregister.split('EXPORT_SYMBOL(nvUvmInterfaceUnregisterGpu);', 1)[0]
        self.assertIn('hybrid580_uvm_pin_quarantined_state();', unregister)
        self.assertIn('pr_emerg(', unregister)
        self.assertIn('NV_STATUS nvUvmInterfaceGetGpuInfo(', self.uvm_bridge)
        self.assertIn('hybrid580_uvm_gpu_route_get_info', self.uvm_bridge)
        self.assertIn('const UvmGpuClientInfo *pGpuClientInfo', self.uvm_bridge)
        self.assertIn('UvmGpuInfo *pGpuInfo', self.uvm_bridge)
        self.assertIn('pGpuClientInfo->hSmcPartRef != 0', self.uvm_bridge)

    def test_uvm_device_lifecycle_routes_by_uuid_owner_and_pins_inconsistent_handles(self):
        self.assertIn('hybrid580_open_nvUvmInterfaceDeviceCreate', self.uvm_bridge)
        self.assertIn('hybrid580_legacy_nvUvmInterfaceDeviceCreate', self.uvm_bridge)
        self.assertIn('hybrid580_open_nvUvmInterfaceDeviceDestroy', self.uvm_bridge)
        self.assertIn('hybrid580_legacy_nvUvmInterfaceDeviceDestroy', self.uvm_bridge)
        create = self.uvm_bridge.split('NV_STATUS nvUvmInterfaceDeviceCreate(', 1)[1]
        create = create.split('EXPORT_SYMBOL(nvUvmInterfaceDeviceCreate);', 1)[0]
        self.assertIn('hybrid580_uvm_device_route_create', create)
        self.assertIn('hybrid580_uvm_sessions.native_open', create)
        self.assertIn('hybrid580_uvm_sessions.native_legacy', create)
        self.assertIn('session != (uvmGpuSessionHandle)&hybrid580_uvm_sessions', create)
        self.assertIn('if (quarantine)', create)
        destroy = self.uvm_bridge.split('void nvUvmInterfaceDeviceDestroy(', 1)[1]
        destroy = destroy.split('EXPORT_SYMBOL(nvUvmInterfaceDeviceDestroy);', 1)[0]
        self.assertIn('hybrid580_uvm_device_route_destroy', destroy)
        self.assertIn('hybrid580_uvm_pin_quarantined_state();', destroy)
        session_destroy = self.uvm_bridge.split('NV_STATUS nvUvmInterfaceSessionDestroy(', 1)[1]
        session_destroy = session_destroy.split('EXPORT_SYMBOL(nvUvmInterfaceSessionDestroy);', 1)[0]
        self.assertIn('hybrid580_uvm_device_registry_count(&hybrid580_uvm_devices) != 0',
                      session_destroy)
        self.assertIn("'nvUvmInterfaceDeviceCreate'", (ROOT / 'tools/build_hybrid_frontend.py').read_text())
        self.assertIn("'nvUvmInterfaceDeviceDestroy'", (ROOT / 'tools/build_hybrid_frontend.py').read_text())

    def test_uvm_device_metadata_calls_route_by_created_handle_owner(self):
        for api in ('GetFbInfo', 'QueryCaps', 'QueryCopyEnginesCaps',
                    'GetEccInfo', 'GetNvlinkInfo'):
            self.assertIn(f'hybrid580_open_nvUvmInterface{api}', self.uvm_bridge)
            self.assertIn(f'hybrid580_legacy_nvUvmInterface{api}', self.uvm_bridge)
            self.assertIn(f'NV_STATUS nvUvmInterface{api}(', self.uvm_bridge)
        self.assertIn('hybrid580_uvm_device_route_call', self.uvm_bridge)
        self.assertIn('hybrid580_uvm_device_registry_lookup', self.uvm_device_route)
        builder_source = (ROOT / 'tools/build_hybrid_frontend.py').read_text()
        for api in ('GetFbInfo', 'QueryCaps', 'QueryCopyEnginesCaps',
                    'GetEccInfo', 'GetNvlinkInfo'):
            self.assertIn(f"'nvUvmInterface{api}'", builder_source)

    def test_uvm_address_spaces_keep_parent_and_provider_until_destroy(self):
        self.assertIn('hybrid580_open_nvUvmInterfaceAddressSpaceCreate', self.uvm_bridge)
        self.assertIn('hybrid580_legacy_nvUvmInterfaceAddressSpaceCreate', self.uvm_bridge)
        self.assertIn('hybrid580_open_nvUvmInterfaceAddressSpaceDestroy', self.uvm_bridge)
        self.assertIn('hybrid580_legacy_nvUvmInterfaceAddressSpaceDestroy', self.uvm_bridge)
        self.assertIn('NV_STATUS nvUvmInterfaceAddressSpaceCreate(', self.uvm_bridge)
        self.assertIn('void nvUvmInterfaceAddressSpaceDestroy(', self.uvm_bridge)
        self.assertIn('hybrid580_uvm_address_space_route_create', self.uvm_bridge)
        self.assertIn('hybrid580_uvm_address_space_route_destroy', self.uvm_bridge)
        self.assertIn('hybrid580_uvm_address_space_registry_has_parent', self.uvm_bridge)
        self.assertIn('kzalloc(sizeof(*entry), GFP_KERNEL)', self.uvm_bridge)
        self.assertIn('kfree(removed);', self.uvm_bridge)
        self.assertIn('hybrid580_uvm_address_space_registry_has_parent',
                      self.uvm_address_space_route)
        builder_source = (ROOT / 'tools/build_hybrid_frontend.py').read_text()
        for api in ('AddressSpaceCreate', 'AddressSpaceDestroy'):
            self.assertIn(f"'nvUvmInterface{api}'", builder_source)

    def test_dup_address_space_uses_device_owner_and_registers_child_lifetime(self):
        self.assertIn('hybrid580_open_nvUvmInterfaceDupAddressSpace', self.uvm_bridge)
        self.assertIn('hybrid580_legacy_nvUvmInterfaceDupAddressSpace', self.uvm_bridge)
        self.assertIn('NV_STATUS nvUvmInterfaceDupAddressSpace(', self.uvm_bridge)
        duplicate = self.uvm_bridge.split(
            'NV_STATUS nvUvmInterfaceDupAddressSpace(', 1)[1]
        duplicate = duplicate.split(
            'EXPORT_SYMBOL(nvUvmInterfaceDupAddressSpace);', 1)[0]
        self.assertIn('hybrid580_uvm_address_space_route_duplicate(', duplicate)
        self.assertIn('staged_info = kzalloc(sizeof(*staged_info), GFP_KERNEL);',
                      duplicate)
        self.assertIn('*vaSpaceInfo = *staged_info;', duplicate)
        route = self.uvm_address_space_route
        self.assertIn('hybrid580_uvm_device_registry_lookup(', route)
        self.assertIn('hybrid580_uvm_address_space_registry_insert(', route)
        builder_source = (ROOT / 'tools/build_hybrid_frontend.py').read_text()
        self.assertIn("'nvUvmInterfaceDupAddressSpace'", builder_source)

    def test_dup_allocation_requires_both_address_spaces_from_same_rm(self):
        for backend in ('open', 'legacy'):
            self.assertIn(f'hybrid580_{backend}_nvUvmInterfaceDupAllocation',
                          self.uvm_bridge)
        self.assertIn('NV_STATUS nvUvmInterfaceDupAllocation(', self.uvm_bridge)
        duplicate = self.uvm_bridge.split(
            'NV_STATUS nvUvmInterfaceDupAllocation(', 1)[1]
        duplicate = duplicate.split(
            'EXPORT_SYMBOL(nvUvmInterfaceDupAllocation);', 1)[0]
        self.assertIn('hybrid580_uvm_address_space_route_dup_allocation(', duplicate)
        self.assertIn('NV_ERR_NOT_SUPPORTED', duplicate)
        route = self.uvm_address_space_route
        self.assertIn('src_provider != dst_provider', route)
        self.assertIn('staged_dst_address', route)
        builder_source = (ROOT / 'tools/build_hybrid_frontend.py').read_text()
        self.assertIn("'nvUvmInterfaceDupAllocation'", builder_source)

    def test_mixed_provider_p2p_caps_are_suppressed_for_uvm_discovery(self):
        for backend in ('open', 'legacy'):
            self.assertIn(f'hybrid580_{backend}_nvUvmInterfaceGetP2PCaps',
                          self.uvm_bridge)
        self.assertIn('NV_STATUS nvUvmInterfaceGetP2PCaps(', self.uvm_bridge)
        query = self.uvm_bridge.split(
            'NV_STATUS nvUvmInterfaceGetP2PCaps(', 1)[1]
        query = query.split('EXPORT_SYMBOL(nvUvmInterfaceGetP2PCaps);', 1)[0]
        self.assertIn('memset(p2pCapsParams, 0, sizeof(*p2pCapsParams));', query)
        self.assertIn('HYBRID580_UVM_DEVICE_PAIR_ROUTE_CROSS_PROVIDER', query)
        self.assertIn('p2pCapsParams->p2pLink = UVM_LINK_TYPE_NONE;', query)
        self.assertIn('hybrid580_uvm_device_route_pair_call(', query)
        builder_source = (ROOT / 'tools/build_hybrid_frontend.py').read_text()
        self.assertIn("'nvUvmInterfaceGetP2PCaps'", builder_source)

    def test_p2p_object_uses_synthetic_handle_and_pins_both_device_parents(self):
        route = (ROOT / 'src/hybrid580_uvm_p2p_object_route.h').read_text()
        for backend in ('open', 'legacy'):
            self.assertIn(f'hybrid580_{backend}_nvUvmInterfaceP2pObjectCreate',
                          self.uvm_bridge)
            self.assertIn(f'hybrid580_{backend}_nvUvmInterfaceP2pObjectDestroy',
                          self.uvm_bridge)
        create = self.uvm_bridge.split(
            'NV_STATUS nvUvmInterfaceP2pObjectCreate(', 1)[1]
        create = create.split(
            'EXPORT_SYMBOL(nvUvmInterfaceP2pObjectCreate);', 1)[0]
        self.assertIn('hybrid580_uvm_p2p_object_route_create(', create)
        self.assertIn('NV_ERR_NOT_SUPPORTED', create)
        self.assertIn('hybrid580_uvm_p2p_object_has_parent', self.uvm_bridge)
        self.assertIn('parent_device1', route)
        self.assertIn('parent_device2', route)
        self.assertIn('HYBRID580_UVM_P2P_PUBLIC_HANDLE_BASE', route)
        destroy = self.uvm_bridge.split(
            'void nvUvmInterfaceP2pObjectDestroy(', 1)[1]
        destroy = destroy.split(
            'EXPORT_SYMBOL(nvUvmInterfaceP2pObjectDestroy);', 1)[0]
        self.assertIn('hybrid580_uvm_p2p_object_route_destroy(', destroy)
        builder_source = (ROOT / 'tools/build_hybrid_frontend.py').read_text()
        for api in ('P2pObjectCreate', 'P2pObjectDestroy'):
            self.assertIn(f"'nvUvmInterface{api}'", builder_source)

    def test_pma_routes_by_native_pointer_owner_and_allows_eviction_reentry(self):
        for backend in ('open', 'legacy'):
            for api in ('GetPmaObject', 'PmaRegisterEvictionCallbacks',
                        'PmaUnregisterEvictionCallbacks', 'PmaAllocPages',
                        'PmaPinPages', 'PmaFreePages'):
                self.assertIn(
                    f'hybrid580_{backend}_nvUvmInterface{api}', self.uvm_bridge)
        create = self.uvm_bridge.split(
            'NV_STATUS nvUvmInterfaceGetPmaObject(', 1)[1]
        create = create.split(
            'EXPORT_SYMBOL(nvUvmInterfaceGetPmaObject);', 1)[0]
        self.assertIn('hybrid580_uvm_device_registry_lookup', create)
        self.assertIn('hybrid580_uvm_pma_registry_record', create)
        self.assertIn('*pPmaPubStats = native_stats;', create)
        self.assertIn('native_pma', self.uvm_pma_route)
        self.assertIn('stats_identity', self.uvm_pma_route)
        self.assertIn('active_calls', self.uvm_pma_route)
        self.assertIn('callbacks_registered', self.uvm_pma_route)

        allocate = self.uvm_bridge.split(
            'NV_STATUS nvUvmInterfacePmaAllocPages(', 1)[1]
        allocate = allocate.split(
            'EXPORT_SYMBOL(nvUvmInterfacePmaAllocPages);', 1)[0]
        self.assertIn('hybrid580_uvm_pma_pin(pPma, &pin)', allocate)
        self.assertIn('ops->allocate_pages(pPma, pageCount, pageSize', allocate)
        self.assertIn('hybrid580_uvm_pma_unpin(&pin, -1);', allocate)
        self.assertLess(allocate.index('hybrid580_uvm_pma_pin('),
                        allocate.index('ops->allocate_pages('))
        self.assertLess(allocate.index('ops->allocate_pages('),
                        allocate.index('hybrid580_uvm_pma_unpin(',
                                       allocate.index('ops->allocate_pages(')))

        destroy = self.uvm_bridge.split(
            'void nvUvmInterfaceDeviceDestroy(', 1)[1]
        destroy = destroy.split(
            'EXPORT_SYMBOL(nvUvmInterfaceDeviceDestroy);', 1)[0]
        self.assertIn('hybrid580_uvm_pma_registry_device_destroy_check', destroy)
        self.assertIn('hybrid580_uvm_pma_registry_release_device', destroy)
        builder_source = (ROOT / 'tools/build_hybrid_frontend.py').read_text()
        for api in ('GetPmaObject', 'PmaRegisterEvictionCallbacks',
                    'PmaUnregisterEvictionCallbacks', 'PmaAllocPages',
                    'PmaPinPages', 'PmaFreePages'):
            self.assertIn(f"'nvUvmInterface{api}'", builder_source)

    def test_external_alloc_queries_require_a_common_backend_owner(self):
        apis = ('GetExternalAllocPtes', 'GetExternalAllocPhysAddrs')
        for backend in ('open', 'legacy'):
            for api in apis:
                self.assertIn(
                    f'hybrid580_{backend}_nvUvmInterface{api}', self.uvm_bridge)
        for api in apis:
            function = self.uvm_bridge.split(
                f'NV_STATUS nvUvmInterface{api}(', 1)[1]
            function = function.split(
                f'EXPORT_SYMBOL(nvUvmInterface{api});', 1)[0]
            self.assertIn('hybrid580_uvm_external_mapping_resolve(', function)
            self.assertIn('gpuExternalMappingInfo' if api == 'GetExternalAllocPtes'
                          else 'gpuExternalPhysAddrInfo', function)
            self.assertIn('hybrid580_open_nvUvmInterface' + api, function)
            self.assertIn('hybrid580_legacy_nvUvmInterface' + api, function)
            self.assertIn('mutex_lock(&hybrid580_uvm_callback_lock);', function)
            self.assertIn('mutex_unlock(&hybrid580_uvm_callback_lock);', function)
        self.assertIn('HYBRID580_UVM_TYPED_CHILD_DUPED_MEMORY',
                      self.uvm_external_mapping_route)
        self.assertIn('space_provider != memory_provider',
                      self.uvm_external_mapping_route)
        self.assertIn('native_memory > (uintptr_t)~(uint32_t)0',
                      self.uvm_external_mapping_route)
        self.assertIn('HYBRID580_UVM_EXTERNAL_MAPPING_PROVIDER_MISMATCH',
                      self.uvm_bridge)
        self.assertIn('return NV_ERR_NOT_SUPPORTED;', self.uvm_bridge)
        builder_source = (ROOT / 'tools/build_hybrid_frontend.py').read_text()
        for api in apis:
            self.assertIn(f"'nvUvmInterface{api}'", builder_source)

    def test_fault_and_access_info_routes_preserve_owner_without_fault_path_mutex(self):
        fault_apis = ('InitFaultInfo', 'DestroyFaultInfo',
                      'HasPendingNonReplayableFaults',
                      'GetNonReplayableFaults', 'FlushReplayableFaultBuffer',
                      'TogglePrefetchFaults')
        access_apis = ('InitAccessCntrInfo', 'DestroyAccessCntrInfo',
                       'EnableAccessCntr', 'DisableAccessCntr')
        for backend in ('open', 'legacy'):
            for api in fault_apis + access_apis:
                self.assertIn(
                    f'hybrid580_{backend}_nvUvmInterface{api}', self.uvm_bridge)
        for api in fault_apis:
            function = self.uvm_bridge.split(
                f'NV_STATUS nvUvmInterface{api}(', 1)[1]
            function = function.split(
                f'EXPORT_SYMBOL(nvUvmInterface{api});', 1)[0]
            if api == 'InitFaultInfo':
                self.assertIn('hybrid580_uvm_info_reserve_fault_pair_locked(', function)
            elif api == 'DestroyFaultInfo':
                self.assertIn('hybrid580_uvm_info_begin_fault_retire_locked(', function)
            else:
                self.assertIn('hybrid580_uvm_info_registry_pin(', function)
        for api in ('HasPendingNonReplayableFaults', 'GetNonReplayableFaults',
                    'FlushReplayableFaultBuffer', 'TogglePrefetchFaults'):
            function = self.uvm_bridge.split(
                f'NV_STATUS nvUvmInterface{api}(', 1)[1]
            function = function.split(
                f'EXPORT_SYMBOL(nvUvmInterface{api});', 1)[0]
            self.assertIn('spin_lock_irqsave(', function)
            self.assertIn('spin_unlock_irqrestore(', function)
            self.assertNotIn('hybrid580_uvm_callback_lock', function)
            self.assertIn('hybrid580_uvm_info_registry_pin(', function)
        self.assertIn('HYBRID580_UVM_INFO_FAULT', self.uvm_info_registry)
        self.assertIn('HYBRID580_UVM_INFO_ACCESS_COUNTER', self.uvm_info_registry)
        self.assertIn('entry->active_calls != 0', self.uvm_info_registry)
        builder_source = (ROOT / 'tools/build_hybrid_frontend.py').read_text()
        for api in fault_apis + access_apis:
            self.assertIn(f"'nvUvmInterface{api}'", builder_source)
        for api in ('InitAccessCntrInfo', 'DestroyAccessCntrInfo'):
            function = self.uvm_bridge.split(
                f'NV_STATUS nvUvmInterface{api}(', 1)[1]
            function = function.split(
                f'EXPORT_SYMBOL(nvUvmInterface{api});', 1)[0]
            helper = ('hybrid580_uvm_info_reserve_locked('
                      if api == 'InitAccessCntrInfo' else
                      'hybrid580_uvm_info_begin_retire_locked(')
            self.assertIn(helper, function)
        for api, backend_call in (
                ('InitFaultInfo', 'ops->init('),
                ('DestroyFaultInfo', 'ops->destroy('),
                ('InitAccessCntrInfo', 'ops->init('),
                ('DestroyAccessCntrInfo', 'ops->destroy('),
                ('EnableAccessCntr', 'ops->enable('),
                ('DisableAccessCntr', 'ops->disable(')):
            function = self.uvm_bridge.split(
                f'NV_STATUS nvUvmInterface{api}(', 1)[1]
            function = function.split(
                f'EXPORT_SYMBOL(nvUvmInterface{api});', 1)[0]
            self.assertLess(function.index('mutex_unlock(&hybrid580_uvm_callback_lock);'),
                            function.index(backend_call))
        destroy_device = self.uvm_bridge.split(
            'void nvUvmInterfaceDeviceDestroy(', 1)[1]
        destroy_device = destroy_device.split(
            'EXPORT_SYMBOL(nvUvmInterfaceDeviceDestroy);', 1)[0]
        self.assertIn('hybrid580_uvm_info_registry_has_parent(', destroy_device)
        self.assertIn('spin_lock_irqsave(&hybrid580_uvm_info_lock', destroy_device)
        finish_destroy = self.uvm_bridge.split(
            'static NV_STATUS hybrid580_uvm_info_finish_retire(', 1)[1]
        finish_destroy = finish_destroy.split(
            'static NV_STATUS hybrid580_uvm_pma_pin(', 1)[0]
        self.assertIn('hybrid580_uvm_info_registry_quarantine(', finish_destroy)
        self.assertIn('hybrid580_uvm_pin_quarantined_state();', finish_destroy)

    def test_page_directory_calls_use_address_space_owner(self):
        for api in ('SetPageDirectory', 'UnsetPageDirectory'):
            self.assertIn(f'hybrid580_open_nvUvmInterface{api}', self.uvm_bridge)
            self.assertIn(f'hybrid580_legacy_nvUvmInterface{api}', self.uvm_bridge)
            self.assertIn(f'NV_STATUS nvUvmInterface{api}(', self.uvm_bridge)
        self.assertIn('hybrid580_uvm_address_space_route_call', self.uvm_bridge)
        self.assertIn('hybrid580_uvm_address_space_route_call',
                      self.uvm_address_space_route)
        set_page_directory = self.uvm_bridge.split(
            'NV_STATUS nvUvmInterfaceSetPageDirectory(', 1)[1]
        set_page_directory = set_page_directory.split(
            'EXPORT_SYMBOL(nvUvmInterfaceSetPageDirectory);', 1)[0]
        self.assertIn('memset(dmaAddress, 0, sizeof(*dmaAddress));', set_page_directory)
        builder_source = (ROOT / 'tools/build_hybrid_frontend.py').read_text()
        for api in ('SetPageDirectory', 'UnsetPageDirectory'):
            self.assertIn(f"'nvUvmInterface{api}'", builder_source)

    def test_page_fault_ownership_and_rm_interrupt_service_route_by_device(self):
        for api in ('OwnPageFaultIntr', 'ServiceDeviceInterruptsRM'):
            self.assertIn(f'hybrid580_open_nvUvmInterface{api}', self.uvm_bridge)
            self.assertIn(f'hybrid580_legacy_nvUvmInterface{api}', self.uvm_bridge)
            self.assertIn(f'NV_STATUS nvUvmInterface{api}(', self.uvm_bridge)
        self.assertIn('hybrid580_uvm_device_call(device,', self.uvm_bridge)
        own = self.uvm_bridge.split('NV_STATUS nvUvmInterfaceOwnPageFaultIntr(', 1)[1]
        own = own.split('EXPORT_SYMBOL(nvUvmInterfaceOwnPageFaultIntr);', 1)[0]
        self.assertIn('bOwnInterrupts != NV_TRUE && bOwnInterrupts != NV_FALSE', own)
        builder_source = (ROOT / 'tools/build_hybrid_frontend.py').read_text()
        for api in ('OwnPageFaultIntr', 'ServiceDeviceInterruptsRM'):
            self.assertIn(f"'nvUvmInterface{api}'", builder_source)

    def test_fault_reporting_routes_device_fault_and_fans_out_global_fatal(self):
        self.assertIn(
            'hybrid580_open_nvUvmInterfaceReportNonReplayableFault',
            self.uvm_bridge)
        self.assertIn(
            'hybrid580_legacy_nvUvmInterfaceReportNonReplayableFault',
            self.uvm_bridge)
        self.assertIn('hybrid580_uvm_device_call(\n        device, &call',
                      self.uvm_bridge)
        report_fault = self.uvm_bridge.split(
            'NV_STATUS nvUvmInterfaceReportNonReplayableFault(', 1)[1]
        report_fault = report_fault.split(
            'EXPORT_SYMBOL(nvUvmInterfaceReportNonReplayableFault);', 1)[0]
        self.assertIn('device == NULL || pFaultPacket == NULL', report_fault)
        fatal = self.uvm_bridge.split(
            'void nvUvmInterfaceReportFatalError(', 1)[1]
        fatal = fatal.split(
            'EXPORT_SYMBOL(nvUvmInterfaceReportFatalError);', 1)[0]
        self.assertIn('hybrid580_open_nvUvmInterfaceReportFatalError(error);', fatal)
        self.assertIn('hybrid580_legacy_nvUvmInterfaceReportFatalError(error);', fatal)
        self.assertNotIn('hybrid580_uvm_callback_lock', fatal)
        builder_source = (ROOT / 'tools/build_hybrid_frontend.py').read_text()
        for api in ('ReportNonReplayableFault', 'ReportFatalError'):
            self.assertIn(f"'nvUvmInterface{api}'", builder_source)

    def test_sriov_only_paging_interfaces_fail_closed(self):
        paging = ('PagingChannelAllocate', 'PagingChannelDestroy',
                  'PagingChannelsMap', 'PagingChannelsUnmap',
                  'PagingChannelPushStream')
        for api in paging:
            signature = ('void' if api in ('PagingChannelDestroy',
                                           'PagingChannelsUnmap') else 'NV_STATUS')
            body = self.uvm_bridge.split(
                f'{signature} nvUvmInterface{api}(', 1)[1]
            body = body.split(
                f'EXPORT_SYMBOL(nvUvmInterface{api});', 1)[0]
            self.assertNotIn('hybrid580_open_nvUvmInterface', body)
            self.assertNotIn('hybrid580_legacy_nvUvmInterface', body)
            self.assertIn(f"'nvUvmInterface{api}'",
                          (ROOT / 'tools/build_hybrid_frontend.py').read_text())
        allocate = self.uvm_bridge.split(
            'NV_STATUS nvUvmInterfacePagingChannelAllocate(', 1)[1]
        allocate = allocate.split(
            'EXPORT_SYMBOL(nvUvmInterfacePagingChannelAllocate);', 1)[0]
        self.assertIn('*channel = NULL;', allocate)
        self.assertIn('memset(channelInfo, 0, sizeof(*channelInfo));', allocate)
        self.assertIn('return NV_ERR_NOT_SUPPORTED;', allocate)
        map_body = self.uvm_bridge.split(
            'NV_STATUS nvUvmInterfacePagingChannelsMap(', 1)[1]
        map_body = map_body.split(
            'EXPORT_SYMBOL(nvUvmInterfacePagingChannelsMap);', 1)[0]
        self.assertIn('*dstAddress = 0;', map_body)
        self.assertIn('return NV_ERR_NOT_SUPPORTED;', map_body)

    def test_csl_contexts_keep_their_rm_owner_and_lifetime(self):
        csl_apis = ('CslInitContext', 'DeinitCslContext', 'CslRotateKey',
                    'CslRotateIv', 'CslEncrypt', 'CslDecrypt', 'CslSign',
                    'CslQueryMessagePool', 'CslIncrementIv',
                    'CslLogEncryption')
        for backend in ('open', 'legacy'):
            for api in csl_apis:
                self.assertIn(
                    f'hybrid580_{backend}_nvUvmInterface{api}',
                    self.uvm_bridge)
        init_fault = self.uvm_bridge.split(
            'NV_STATUS nvUvmInterfaceInitFaultInfo(', 1)[1]
        init_fault = init_fault.split(
            'EXPORT_SYMBOL(nvUvmInterfaceInitFaultInfo);', 1)[0]
        self.assertIn('hybrid580_uvm_info_reserve_fault_pair_locked(', init_fault)
        destroy_fault = self.uvm_bridge.split(
            'NV_STATUS nvUvmInterfaceDestroyFaultInfo(', 1)[1]
        destroy_fault = destroy_fault.split(
            'EXPORT_SYMBOL(nvUvmInterfaceDestroyFaultInfo);', 1)[0]
        self.assertIn('hybrid580_uvm_info_begin_fault_retire_locked(',
                      destroy_fault)
        init_context = self.uvm_bridge.split(
            'NV_STATUS nvUvmInterfaceCslInitContext(', 1)[1]
        init_context = init_context.split(
            'EXPORT_SYMBOL(nvUvmInterfaceCslInitContext);', 1)[0]
        self.assertIn('hybrid580_uvm_channel_owner_locked(', init_context)
        self.assertIn('hybrid580_uvm_info_reserve_locked(', init_context)
        self.assertIn('hybrid580_uvm_info_registry_set_channel_parent(',
                      init_context)
        deinit = self.uvm_bridge.split(
            'void nvUvmInterfaceDeinitCslContext(', 1)[1]
        deinit = deinit.split(
            'EXPORT_SYMBOL(nvUvmInterfaceDeinitCslContext);', 1)[0]
        self.assertIn('HYBRID580_UVM_INFO_CSL', deinit)
        for api in csl_apis[2:]:
            function = self.uvm_bridge.split(
                f'NV_STATUS nvUvmInterface{api}(', 1)[1]
            function = function.split(
                f'EXPORT_SYMBOL(nvUvmInterface{api});', 1)[0]
            expected_pin = (
                'hybrid580_uvm_info_registry_pin_many_same_provider('
                if api == 'CslRotateKey' else 'hybrid580_uvm_csl_pin(')
            self.assertIn(expected_pin, function)
            self.assertNotIn('hybrid580_uvm_callback_lock', function)
        rotate = self.uvm_bridge.split(
            'NV_STATUS nvUvmInterfaceCslRotateKey(', 1)[1]
        rotate = rotate.split('EXPORT_SYMBOL(nvUvmInterfaceCslRotateKey);', 1)[0]
        self.assertIn('hybrid580_uvm_info_registry_pin_many_same_provider(', rotate)
        self.assertIn('HYBRID580_UVM_INFO_CROSS_PROVIDER',
                      self.uvm_info_registry)
        self.assertIn('provider', rotate)
        self.assertIn('HYBRID580_UVM_INFO_CSL', self.uvm_info_registry)
        self.assertIn('parent_identity', self.uvm_info_registry)
        self.assertNotRegex(
            self.uvm_bridge,
            r'uvmCslContext\s*->\s*(?:ctx|nvidia_stack)')
        channel_destroy = self.uvm_bridge.split(
            'void nvUvmInterfaceChannelDestroy(', 1)[1]
        channel_destroy = channel_destroy.split(
            'EXPORT_SYMBOL(nvUvmInterfaceChannelDestroy);', 1)[0]
        self.assertIn('hybrid580_uvm_info_registry_quarantine_channel_parent(',
                      channel_destroy)
        builder_source = (ROOT / 'tools/build_hybrid_frontend.py').read_text()
        for api in csl_apis:
            self.assertIn(f"'nvUvmInterface{api}'", builder_source)

    def test_memory_allocation_and_cpu_mapping_route_by_address_space_owner(self):
        apis = ('MemoryAllocFB', 'MemoryAllocSys', 'MemoryFree',
                'MemoryCpuMap', 'MemoryCpuUnMap')
        for api in apis:
            self.assertIn(f'hybrid580_open_nvUvmInterface{api}', self.uvm_bridge)
            self.assertIn(f'hybrid580_legacy_nvUvmInterface{api}', self.uvm_bridge)
            signature = 'void' if api in ('MemoryFree', 'MemoryCpuUnMap') else 'NV_STATUS'
            self.assertIn(f'{signature} nvUvmInterface{api}(', self.uvm_bridge)
        alloc_helper = self.uvm_bridge.split(
            'static NV_STATUS hybrid580_uvm_memory_alloc(', 1)[1]
        alloc_helper = alloc_helper.split(
            'NV_STATUS nvUvmInterfaceMemoryAllocFB(', 1)[0]
        self.assertIn('hybrid580_uvm_address_space_call(', alloc_helper)
        for api in ('MemoryCpuMap', 'MemoryFree', 'MemoryCpuUnMap'):
            signature = 'void' if api in ('MemoryFree', 'MemoryCpuUnMap') else 'NV_STATUS'
            body = self.uvm_bridge.split(
                f'{signature} nvUvmInterface{api}(', 1)[1]
            body = body.split(f'EXPORT_SYMBOL(nvUvmInterface{api});', 1)[0]
            self.assertIn('hybrid580_uvm_address_space_call(', body)
        self.assertIn('*gpuPointer = 0;', alloc_helper)
        self.assertIn('args->backend_gpu_pointer != 0', self.uvm_bridge)
        self.assertIn('args->ambiguous_output = 1;', self.uvm_bridge)
        self.assertIn('args->backend_cpu_pointer != NULL', self.uvm_bridge)
        self.assertIn('status = NV_ERR_GENERIC;', self.uvm_bridge)
        cpu_map = self.uvm_bridge.split('NV_STATUS nvUvmInterfaceMemoryCpuMap(', 1)[1]
        cpu_map = cpu_map.split('EXPORT_SYMBOL(nvUvmInterfaceMemoryCpuMap);', 1)[0]
        self.assertIn('*cpuPtr = NULL;', cpu_map)
        builder_source = (ROOT / 'tools/build_hybrid_frontend.py').read_text()
        for api in apis:
            self.assertIn(f"'nvUvmInterface{api}'", builder_source)

    def test_dup_memory_handles_are_provider_and_device_owned_until_free(self):
        route = (ROOT / 'src/hybrid580_uvm_dup_memory_route.h').read_text()
        for api in ('DupMemory', 'FreeDupedHandle'):
            self.assertIn(f'hybrid580_open_nvUvmInterface{api}', self.uvm_bridge)
            self.assertIn(f'hybrid580_legacy_nvUvmInterface{api}', self.uvm_bridge)
            self.assertIn(f'NV_STATUS nvUvmInterface{api}(', self.uvm_bridge)
        duplicate = self.uvm_bridge.split(
            'NV_STATUS nvUvmInterfaceDupMemory(', 1)[1]
        duplicate = duplicate.split(
            'EXPORT_SYMBOL(nvUvmInterfaceDupMemory);', 1)[0]
        self.assertIn('hybrid580_uvm_dup_memory_route_duplicate(', duplicate)
        self.assertIn('staged_info = kzalloc(sizeof(*staged_info), GFP_KERNEL);',
                      duplicate)
        release = self.uvm_bridge.split(
            'NV_STATUS nvUvmInterfaceFreeDupedHandle(', 1)[1]
        release = release.split(
            'EXPORT_SYMBOL(nvUvmInterfaceFreeDupedHandle);', 1)[0]
        self.assertIn('hybrid580_uvm_dup_memory_route_release(', release)
        self.assertIn('HYBRID580_UVM_TYPED_CHILD_PARENT_DEVICE', route)
        self.assertIn('HYBRID580_UVM_TYPED_CHILD_DUPED_MEMORY', route)
        destroy = self.uvm_bridge.split(
            'void nvUvmInterfaceDeviceDestroy(', 1)[1]
        destroy = destroy.split(
            'EXPORT_SYMBOL(nvUvmInterfaceDeviceDestroy);', 1)[0]
        self.assertIn('HYBRID580_UVM_TYPED_CHILD_PARENT_DEVICE', destroy)
        builder_source = (ROOT / 'tools/build_hybrid_frontend.py').read_text()
        for api in ('DupMemory', 'FreeDupedHandle'):
            self.assertIn(f"'nvUvmInterface{api}'", builder_source)

    def test_tsg_and_channel_lifetimes_route_by_typed_parent_owner(self):
        child_route = (ROOT / 'src/hybrid580_uvm_typed_child_route.h').read_text()
        for api in ('TsgAllocate', 'TsgDestroy', 'ChannelAllocate', 'ChannelDestroy'):
            self.assertIn(f'hybrid580_open_nvUvmInterface{api}', self.uvm_bridge)
            self.assertIn(f'hybrid580_legacy_nvUvmInterface{api}', self.uvm_bridge)
            signature = 'void' if api.endswith('Destroy') else 'NV_STATUS'
            self.assertIn(f'{signature} nvUvmInterface{api}(', self.uvm_bridge)
        self.assertIn('HYBRID580_UVM_TYPED_CHILD_TSG', child_route)
        self.assertIn('HYBRID580_UVM_TYPED_CHILD_CHANNEL', child_route)
        self.assertIn('parent_identity', child_route)
        self.assertIn('hybrid580_uvm_typed_child_registry_has_parent', child_route)
        self.assertIn('hybrid580_uvm_typed_child_route_call', child_route)
        self.assertIn('hybrid580_uvm_typed_child_route_destroy', child_route)
        self.assertIn('hybrid580_uvm_typed_child_registry_has_parent', self.uvm_bridge)
        tsg = self.uvm_bridge.split(
            'NV_STATUS nvUvmInterfaceTsgAllocate(', 1)[1]
        tsg = tsg.split('EXPORT_SYMBOL(nvUvmInterfaceTsgAllocate);', 1)[0]
        self.assertIn('*tsg = NULL;', tsg)
        self.assertIn('hybrid580_uvm_address_space_route_call(', tsg)
        self.assertIn('hybrid580_uvm_typed_child_registry_insert(', tsg)
        self.assertLess(tsg.index('hybrid580_uvm_typed_child_registry_insert('),
                        tsg.index('*tsg = (uvmGpuTsgHandle)params.native_tsg;'))
        channel = self.uvm_bridge.split(
            'NV_STATUS nvUvmInterfaceChannelAllocate(', 1)[1]
        channel = channel.split('EXPORT_SYMBOL(nvUvmInterfaceChannelAllocate);', 1)[0]
        self.assertIn('*channel = NULL;', channel)
        self.assertIn('memset(channelInfo, 0, sizeof(*channelInfo));', channel)
        self.assertIn('hybrid580_uvm_typed_child_route_call(', channel)
        self.assertIn('params.provider', channel)
        address_space_destroy = self.uvm_bridge.split(
            'void nvUvmInterfaceAddressSpaceDestroy(', 1)[1]
        address_space_destroy = address_space_destroy.split(
            'EXPORT_SYMBOL(nvUvmInterfaceAddressSpaceDestroy);', 1)[0]
        self.assertIn('hybrid580_uvm_typed_child_registry_has_parent(',
                      address_space_destroy)
        builder_source = (ROOT / 'tools/build_hybrid_frontend.py').read_text()
        for api in ('TsgAllocate', 'TsgDestroy', 'ChannelAllocate', 'ChannelDestroy'):
            self.assertIn(f"'nvUvmInterface{api}'", builder_source)

    def test_retained_channel_and_resource_pte_routes_preserve_provider(self):
        route = (ROOT / 'src/hybrid580_uvm_typed_child_route.h').read_text()
        apis = ('RetainChannel', 'BindChannelResources', 'ReleaseChannel',
                'StopChannel', 'GetChannelResourcePtes')
        for api in apis:
            self.assertIn(f'hybrid580_open_nvUvmInterface{api}', self.uvm_bridge)
            self.assertIn(f'hybrid580_legacy_nvUvmInterface{api}', self.uvm_bridge)
            signature = 'void' if api in ('ReleaseChannel', 'StopChannel') else 'NV_STATUS'
            self.assertIn(f'{signature} nvUvmInterface{api}(', self.uvm_bridge)
        self.assertIn('HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL', route)
        retain = self.uvm_bridge.split(
            'NV_STATUS nvUvmInterfaceRetainChannel(', 1)[1]
        retain = retain.split('EXPORT_SYMBOL(nvUvmInterfaceRetainChannel);', 1)[0]
        self.assertIn('*retainedChannel = NULL;', retain)
        self.assertIn('params = kzalloc(sizeof(*params), GFP_KERNEL);', retain)
        self.assertIn('kfree(params);', retain)
        self.assertIn('hybrid580_uvm_address_space_route_call(', retain)
        self.assertIn('hybrid580_uvm_typed_child_registry_insert(', retain)
        self.assertIn('entry_published = entry->identity != 0;', retain)
        self.assertIn('refcounted', route)
        for api, signature in (('BindChannelResources', 'NV_STATUS'),
                               ('StopChannel', 'void')):
            body = self.uvm_bridge.split(
                f'{signature} nvUvmInterface{api}(', 1)[1]
            body = body.split(f'EXPORT_SYMBOL(nvUvmInterface{api});', 1)[0]
            self.assertIn('HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL', body)
            self.assertIn('hybrid580_uvm_typed_child_route_call(', body)
        release = self.uvm_bridge.split(
            'void nvUvmInterfaceReleaseChannel(', 1)[1]
        release = release.split('EXPORT_SYMBOL(nvUvmInterfaceReleaseChannel);', 1)[0]
        self.assertIn('hybrid580_uvm_typed_child_route_destroy(', release)
        ptes = self.uvm_bridge.split(
            'NV_STATUS nvUvmInterfaceGetChannelResourcePtes(', 1)[1]
        ptes = ptes.split('EXPORT_SYMBOL(nvUvmInterfaceGetChannelResourcePtes);', 1)[0]
        self.assertIn('hybrid580_uvm_address_space_call(', ptes)
        builder_source = (ROOT / 'tools/build_hybrid_frontend.py').read_text()
        for api in apis:
            self.assertIn(f"'nvUvmInterface{api}'", builder_source)

    def test_observed_p2p_controls_are_typed_and_translate_tracked_handles(self):
        for command in ('NV503C_CTRL_CMD_REGISTER_VA_SPACE',
                        'NV503C_CTRL_CMD_UNREGISTER_VA_SPACE',
                        'NV503C_CTRL_CMD_REGISTER_VIDMEM',
                        'NV503C_CTRL_CMD_UNREGISTER_VIDMEM'):
            self.assertIn(command, self.source)
        self.assertIn('hybrid_front_p2p_control_ioctl', self.source)
        self.assertIn('p2p->class_id != NV50_THIRD_PARTY_P2P', self.source)
        self.assertIn('vaspace->class_id != FERMI_VASPACE_A', self.source)
        self.assertIn('memory->class_id != NV01_MEMORY_LOCAL_USER', self.source)
        self.assertIn('backend_params.hVASpace = vaspace->backend_handle', self.source)
        self.assertIn('backend_params.hMemory = memory->backend_handle', self.source)
        self.assertIn('p2p->backend != HYBRID580_BACKEND_LEGACY', self.source)
        self.assertIn('NV503C_CTRL_CMD_REGISTER_PID', self.source)
        self.assertIn('return -ENOTTY;', self.source)
        self.assertIn('NvU32 p2p_registration_refs;', self.source)
        self.assertIn('if (object->p2p_registration_refs != 0)', self.source)
        self.assertIn('++vaspace->p2p_registration_refs', self.source)
        self.assertIn('--memory->p2p_registration_refs', self.source)

    def test_binapi_is_a_tracked_subdevice_child_with_strict_fixed_parameters(self):
        self.assertIn('hybrid_front_binapi_alloc64', self.source)
        self.assertIn('NV2081_BINAPI', self.source)
        self.assertIn('parent->class_id != NV20_SUBDEVICE_0', self.source)
        self.assertIn('user_params->reserved != 0', self.source)
        self.assertIn('object->class_id == NV2081_BINAPI', self.source)
        self.assertIn('binapi_params_valid', self.source)

    def test_subdevice_and_gr_control_are_a_typed_tracked_path(self):
        self.assertIn('NV20_SUBDEVICE_0', self.source)
        self.assertIn('hybrid_front_subdevice_alloc64', self.source)
        self.assertIn('hybrid_front_gr_tpc_mask_ioctl', self.source)
        self.assertIn('hybrid_front_find_object(root, control->hObject)', self.source)
        self.assertIn('subdevice->backend_parent_handle != device->backend_handle', self.source)
        self.assertIn('control.paramsSize != sizeof(params)', self.source)
        self.assertIn('NV2080_CTRL_CMD_GR_GET_TPC_MASK', self.source)
        self.assertIn('subDeviceId != 0', self.source)

    def test_context_share_alloc_is_a_typed_group_child_route(self):
        self.assertIn('hybrid_front_context_share_alloc64', self.source)
        self.assertIn('FERMI_CONTEXT_SHARE_A', self.source)
        self.assertIn('hybrid580_open_control_session_context_share_alloc_v1', self.source)
        self.assertIn('hybrid580_legacy_control_session_context_share_alloc_v1', self.source)
        self.assertIn('group->vaspace_handle != params->hVASpace', self.source)
        self.assertIn('backend_params.hVASpace = vaspace->backend_handle', self.source)

    def test_channel_alloc_is_architecture_class_allowlisted_and_tracks_lifetimes(self):
        self.assertIn('hybrid_front_channel_alloc64', self.source)
        self.assertIn('BLACKWELL_CHANNEL_GPFIFO_A', self.source)
        self.assertIn('VOLTA_CHANNEL_GPFIFO_A', self.source)
        self.assertIn('hybrid580_open_control_session_channel_alloc_v1', self.source)
        self.assertIn('hybrid580_legacy_control_session_channel_alloc_v1', self.source)
        self.assertIn('object->parent_handle = group->handle', self.source)
        self.assertIn('object->context_share_handle = frontend_handles.context_share', self.source)
        self.assertIn('object->vaspace_handle = group->vaspace_handle', self.source)

    def test_channel_flags_allow_only_physical_and_observed_runqueue_modes(self):
        self.assertIn('hybrid_front_channel_flags_valid', self.source)
        self.assertIn('NVOS04_FLAGS_GROUP_CHANNEL_RUNQUEUE_ONE << 4U', self.source)
        self.assertIn('(flags & ~allowed_mask) == 0', self.source)
        self.assertIn('!hybrid_front_channel_flags_valid(params->flags)', self.source)

    def test_probed_ids_use_typed_backend_calls_and_catalog_namespace_translation(self):
        self.assertIn('hybrid_front_probed_ids', self.source)
        self.assertIn('NV0000_CTRL_CMD_GPU_GET_PROBED_IDS', self.source)
        self.assertIn('hybrid580_legacy_control_session_probed_ids_v1', self.source)
        self.assertIn('hybrid580_open_control_session_probed_ids_v1', self.source)
        self.assertIn('hybrid580_gpu_catalog_merge_probed_ids_v1', self.source)
        self.assertIn('NV0000_CTRL_GPU_MAX_PROBED_GPUS', self.source)
        self.assertIn('BUILD_BUG_ON(', self.source)

    def test_attached_ids_merge_only_validated_ids_from_both_rms(self):
        self.assertIn('hybrid_front_attached_ids', self.source)
        self.assertIn('NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS', self.source)
        self.assertIn('hybrid580_legacy_control_session_attached_ids_v1', self.source)
        self.assertIn('hybrid580_open_control_session_attached_ids_v1', self.source)
        self.assertIn('NV0000_CTRL_GPU_INVALID_ID', self.source)

    def test_control_ioctl_creates_a_bdf_selected_frontend_gpu_descriptor(self):
        self.assertIn('hybrid_front_open_gpu_fd', self.source)
        self.assertIn('hybrid580_open_gpu_session_create_by_bdf_v1', self.source)
        self.assertIn('hybrid580_legacy_gpu_session_create_by_bdf_v1', self.source)
        self.assertIn('fd_install(', self.source)

    def test_gpu_file_dispatch_and_projection_are_backend_specific(self):
        self.assertIn('hybrid_front_gpu_ioctl', self.source)
        self.assertIn('hybrid_front_project_legacy', self.source)
        self.assertIn('hybrid_front_project_open', self.source)
        self.assertIn('hybrid580_legacy_gpu_session_ioctl_v1', self.source)
        self.assertIn('hybrid580_open_gpu_session_ioctl_v1', self.source)
        self.assertIn('base->kind == HYBRID_FRONT_GPU_FILE', self.source)

    def test_gpu_mmap_transfers_vma_ownership_to_the_selected_native_file(self):
        self.assertIn('hybrid_front_gpu_mmap', self.source)
        self.assertIn('.mmap = hybrid_front_gpu_mmap', self.source)
        self.assertIn('vma_set_file(vma, back)', self.source)
        self.assertIn('back->f_op->mmap(back, vma)', self.source)
        self.assertIn('fput(back)', self.source)

    def test_gpu_poll_delegates_without_sleeping_lock_to_selected_native_file(self):
        self.assertIn('hybrid_front_gpu_poll', self.source)
        self.assertIn('.poll = hybrid_front_gpu_poll', self.source)
        segment = self.source[self.source.index('static __poll_t hybrid_front_gpu_poll'):]
        segment = segment[:segment.index('\nstatic bool hybrid_front_bdf_valid')]
        self.assertIn('gpu->file(gpu->session)', segment)
        self.assertIn('back->f_op->poll(back, wait)', segment)
        self.assertIn('READ_ONCE(front->f_flags) & O_NONBLOCK', segment)
        self.assertIn('WRITE_ONCE(back->f_flags, back_flags)', segment)
        self.assertIn('fput(back)', segment)
        self.assertNotIn('mutex_lock', segment)
        self.assertNotIn('mutex_unlock', segment)

    def test_gpu_and_control_files_use_registered_projection_fops_and_bdf_owner(self):
        self.assertNotIn('hybrid_gpu_fops', self.source)
        self.assertIn('anon_inode_getfile("hybrid580-gpu", &hybrid_front_fops', self.source)
        create = self.source[self.source.index('static int hybrid_front_gpu_file_create('):
                             self.source.index('static int hybrid_front_open_gpu_fd(')]
        self.assertIn('entry->backend == HYBRID580_BACKEND_LEGACY', create)
        self.assertIn('entry->backend == HYBRID580_BACKEND_OPEN', create)
        self.assertIn('return rc == -EXDEV ? -ENODEV : rc;', create)
        segment = self.source[self.source.index('static int hybrid_front_open_gpu_fd('):]
        self.assertIn('HYBRID_FRONT_GPU_PRIVATE_ASSOCIATION', segment)
        self.assertLess(segment.index('copy_to_user('), segment.index('fd_install('))

    def test_private_test_abi_is_versioned_and_rejects_noncanonical_requests(self):
        header = (ROOT / 'src/hybrid580_ioctl.h').read_text()
        self.assertIn('HYBRID580_OPEN_GPU_V1 1U', header)
        self.assertIn('_IOWR(HYBRID580_IOCTL_MAGIC, HYBRID580_OPEN_GPU_V1', header)
        segment = self.source[self.source.index('static int hybrid_front_open_gpu_fd'):]
        for field in ('struct_size', 'flags', 'gpu_fd', 'backend', 'reserved[0]', 'reserved[1]'):
            self.assertIn(field, segment)
        self.assertIn('bdf[11] <= \'7\'', self.source)

    def test_register_fd_model_requires_gpu_and_control_projection_to_match(self):
        harness = (ROOT / 'tests/test_hybrid_frontend.py').read_text()
        self.assertIn('_IOC_NR(command)==NV_ESC_REGISTER_FD', harness)
        self.assertIn('hybrid_front_gpu_register_fd_xfer', self.source)
        self.assertIn('_IOC_NR(command) == NV_ESC_IOCTL_XFER_CMD', self.source)
        self.assertIn('register_fd_matches==register_fd_calls', harness)
        self.assertIn('struct fake_register_fd_payload { int ctl_fd; }', harness)

    def test_catalog_is_snapshotted_before_publish_and_served_through_versioned_private_abi(self):
        self.assertIn('hybrid_front_catalog_create', self.source)
        self.assertIn('hybrid580_legacy_gpu_inventory_v1', self.source)
        self.assertIn('hybrid580_open_gpu_inventory_v1', self.source)
        self.assertIn('hybrid580_legacy_gpu_card_info_v1', self.source)
        self.assertIn('hybrid580_open_gpu_card_info_v1', self.source)
        self.assertIn('NV_ESC_CARD_INFO', self.source)
        self.assertIn('hybrid580_gpu_catalog_build_v1', self.source)
        self.assertIn('frontend_gpu_id', (ROOT / 'src/hybrid580-gpu-catalog.h').read_text())
        control_open = self.source[self.source.index('static int hybrid_front_control_state_open('):
                                   self.source.index('static int hybrid_front_open_standard_gpu(')]
        self.assertLess(control_open.index('hybrid_front_catalog_create('),
                        control_open.index('front->private_data = state'))
        opened = self.source[self.source.index('static int hybrid_front_open_inner('):
                             self.source.index('static int hybrid_front_open(')]
        self.assertIn('hybrid580_standard_nodes_resolve_v1', opened)
        self.assertIn('hybrid_front_control_state_open(front, true)', opened)
        self.assertIn('hybrid580_gpu_catalog_v1 *catalog', self.source)
        self.assertIn('kvzalloc(sizeof(*catalog), GFP_KERNEL)', self.source)
        self.assertIn('kvcalloc(HYBRID580_GPU_MAX_BACKEND_DEVICES', self.source)
        self.assertIn('kvfree(state->catalog)', self.source)
        self.assertIn('HYBRID580_IOCTL_GET_GPU_COUNT', self.source)
        self.assertIn('HYBRID580_IOCTL_GET_GPU_INFO', self.source)
        uapi = (ROOT / 'src/hybrid580_ioctl.h').read_text()
        self.assertIn('struct hybrid580_gpu_count_v1', uapi)
        self.assertIn('struct hybrid580_gpu_info_v1', uapi)


if __name__ == '__main__':
    unittest.main()
