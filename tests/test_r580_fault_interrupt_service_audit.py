# SPDX-License-Identifier: MIT
"""Tests for the source-pinned R580 RM non-replayable interrupt audit."""
import importlib.util
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location(
    "r580_fault_interrupt_service_audit",
    ROOT / "tools/audit_r580_fault_interrupt_service.py")
AUDIT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(AUDIT)


def write_source_tree(root: Path, *, method_id="0x20801702", report_stuck=True):
    stuck_handler = (
        "static NvBool _intrServiceStallExactList(void) {"
        " if (bIntrStuck) { NV_ASSERT(0); return NV_FALSE; }"
        " return bPending; }"
        if report_stuck else
        "static NvBool _intrServiceStallExactList(void) { return bPending; }"
    )
    files = {
        "kernel-open/common/inc/nv_uvm_types.h": """
            // Shadow buffer for non-replayable faults on cpu memory. Resman copies
            // here the non-replayable faults that need to be handled by UVM
            void *shadowBufferAddress;
        """,
        "kernel-open/common/inc/nv_uvm_interface.h": """
            /* nvUvmInterfaceHasPendingNonReplayableFaults
               This function tells whether there are pending non-replayable faults
               in the client shadow fault buffer ready to be consumed.
               This function DOES NOT acquire the RM API or GPU locks.
            */
            NV_STATUS nvUvmInterfaceHasPendingNonReplayableFaults(void) { return NV_OK; }
            /* nvUvmInterfaceGetNonReplayableFaults
               This function consumes all non-replayable fault packets in the
               client shadow fault buffer and copies them to the given buffer.
               The shadow fault buffer is a circular queue.
               This function DOES NOT acquire the RM API or GPU locks.
            */
            NV_STATUS nvUvmInterfaceGetNonReplayableFaults(void) { return NV_OK; }
        """,
        "kernel-open/nvidia/nv_uvm_interface.c": """
            NV_STATUS nvUvmInterfaceServiceDeviceInterruptsRM(void *device) {
                return rm_gpu_ops_service_device_interrupts_rm(device);
            }
            NV_STATUS nvUvmInterfaceHasPendingNonReplayableFaults(void) {
                return rm_gpu_ops_has_pending_non_replayable_faults(pFaultInfo->nonReplayable.isr_sp,
                                                                     pFaultInfo, pending);
            }
            NV_STATUS nvUvmInterfaceGetNonReplayableFaults(void) {
                return rm_gpu_ops_get_non_replayable_faults(pFaultInfo->nonReplayable.isr_bh_sp,
                                                             pFaultInfo, faults, count);
            }
        """,
        "src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080mc.h": f"""
            /* This command instructs the RM to service interrupts for the specified engine(s). */
            #define NV2080_CTRL_CMD_MC_SERVICE_INTERRUPTS ({method_id})
            #define NV2080_CTRL_MC_ENGINE_ID_ALL 0xFFFFFFFF
            typedef struct NV2080_CTRL_MC_SERVICE_INTERRUPTS_PARAMS {{ NvU32 engines; }}
                NV2080_CTRL_MC_SERVICE_INTERRUPTS_PARAMS;
        """,
        "src/nvidia/src/kernel/rmapi/nv_gpu_ops.c": """
            NV_STATUS nvGpuOpsServiceDeviceInterruptsRM(void) {
                NV2080_CTRL_MC_SERVICE_INTERRUPTS_PARAMS params = {0};
                params.engines = NV2080_CTRL_MC_ENGINE_ID_ALL;
                status = pRmApi->Control(client, object, NV2080_CTRL_CMD_MC_SERVICE_INTERRUPTS,
                                         &params, sizeof(params));
                return status;
            }
        """,
        "src/nvidia/arch/nvalloc/unix/src/rm-gpu-ops.c": """
            NV_STATUS rm_gpu_ops_service_device_interrupts_rm(void) {
                NV_ENTER_RM_RUNTIME(sp, fp);
                rmStatus = nvGpuOpsServiceDeviceInterruptsRM(device);
                NV_EXIT_RM_RUNTIME(sp, fp);
                return rmStatus;
            }
        """,
        "src/nvidia/src/kernel/gpu/intr/intr.c": """
            NV_STATUS subdeviceCtrlCmdMcServiceInterrupts_IMPL(void) {
                if (pServiceInterruptParams->engines == NV2080_CTRL_MC_ENGINE_ID_ALL)
                    bitVectorSetAll(&engines);
                intrServiceStallList_HAL(pGpu, pIntr, &engines, NV_TRUE);
                return NV_OK;
            }
            void intrServiceStallList_IMPL(void) {
                do {
                    intrGetPendingStall_HAL(pGpu, pIntr, &exactEngines, NULL);
                    bPending = _intrServiceStallExactList(pGpu, pIntr, &exactEngines);
                } while (bPending && bLoop);
            }
        """ + stuck_handler + """
            void intrGetGmmuInterrupts_IMPL(void) {
                if (portAtomicOrS32(kgmmuGetFatalFaultIntrPendingState(gmmu), 0))
                    bitVectorSet(pEngines, MC_ENGINE_IDX_GMMU);
            }
            void intrSetIntrEn_IMPL(Intr *pIntr, NvU32 intrEn0) {
                if (pIntr->halIntrEnabled == NV_FALSE) {
                    NV_PRINTF(LEVEL_INFO,
                              "intrSetIntrEn: set interrupt refused since interrupts are disabled in the HAL\\n");
                    return;
                }
                NV_ASSERT(intrEn0 <= INTERRUPT_TYPE_MAX);
                pIntr->intrEn0 = intrEn0;
            }
        """ + ("" if report_stuck else ""),
        "src/nvidia/src/kernel/gpu/intr/arch/pascal/intr_gp100.c": """
            void intrGetAuxiliaryPendingStall_GP100(void) {
                if (bGetAll || engIdx == MC_ENGINE_IDX_GMMU)
                    intrGetGmmuInterrupts(pGpu, pIntr, pEngines, pThreadState);
            }
        """,
        "src/nvidia/src/kernel/gpu/mmu/kern_gmmu.c": """
            void kgmmuRegisterIntrService_IMPL(void) {
                static NvU16 physicalEngineIdxList[] = {
                    MC_ENGINE_IDX_NON_REPLAYABLE_FAULT,
                    MC_ENGINE_IDX_NON_REPLAYABLE_FAULT_ERROR
                };
                if (!IS_GSP_CLIENT(pGpu))
                    register_kernel_gmmu_intr_service(physicalEngineIdxList);
            }
            NvU32 kgmmuServiceInterrupt_IMPL(void) {
                switch (pParams->engineIdx) {
                case MC_ENGINE_IDX_NON_REPLAYABLE_FAULT:
                    // Copy from HW fault buffer always happens in the top half.
                    // This servicing is merely copying from the SW fault buffer.
                    status = kgmmuServiceNonReplayableFault_HAL(pGpu, pKernelGmmu);
                    break;
                }
                return 0;
            }
        """,
        "src/nvidia/generated/g_subdevice_nvoc.c": """
            { .pFunc = subdeviceCtrlCmdMcServiceInterrupts_IMPL,
              .methodId = 0x20801702u,
              .func = "subdeviceCtrlCmdMcServiceInterrupts" },
        """,
        "kernel-open/nvidia/nv.c": """
            irqreturn_t nvidia_isr(void) {
                rm_gpu_handle_mmu_faults(sp, nv, &faultsCopied);
                if (nv_uvm_event_interrupt(uuid) == NV_OK)
                    uvm_handled = NV_TRUE;
                rm_isr(sp, nv, &need_bottom_half);
            }
            irqreturn_t nvidia_isr_msix(void) {
                NV_SPIN_LOCK(&nvl->msix_isr_lock);
                ret = nvidia_isr(irq, arg);
                NV_SPIN_UNLOCK(&nvl->msix_isr_lock);
                return ret;
            }
            int nv_init_device(void) {
                return request_threaded_irq(nv->interrupt_line, nvidia_isr,
                                             nvidia_isr_kthread_bh, flags, name, nvl);
            }
            int nv_suspend_devices(nv_pm_action_t pm_action,
                                   nv_pm_action_depth_t pm_action_depth) {
                nvidia_modeset_suspend(0);
                if (pm_action_depth == NV_PM_ACTION_DEPTH_MODESET) {
                    return NV_OK;
                }
                nv_preempt_user_channels();
                nv_uvm_suspend();
                if (pm_action_depth == NV_PM_ACTION_DEPTH_UVM) {
                    return NV_OK;
                }
                nvidia_suspend(dev, pm_action, NV_TRUE);
                return NV_OK;
            }
            int nv_pmops_suspend(struct device *dev) {
                return nvidia_suspend(dev, NV_PM_ACTION_STANDBY, NV_FALSE);
            }
            int nvidia_suspend(void) {
                return nv_power_management(nv, pm_action);
            }
            int nv_power_management(void) {
                status = rm_power_management(sp, nv, pm_action);
                nv_kthread_q_stop(&nvl->bottom_half_q);
                return status;
            }
            void nv_shutdown_adapter(void) {
                rm_disable_adapter(sp, nv);
                free_irq(nv->interrupt_line, nvl);
            }
        """,
        "kernel-open/nvidia/nv-procfs.c": """
            int nv_procfs_write_suspend_depth(void) {
                if (strcasecmp(kbuf, "uvm") == 0) {
                    nv_pm_action_depth = NV_PM_ACTION_DEPTH_UVM;
                } else if (strcasecmp(kbuf, "modeset") == 0) {
                    nv_pm_action_depth = NV_PM_ACTION_DEPTH_MODESET;
                } else if (strcasecmp(kbuf, "default") == 0) {
                    nv_pm_action_depth = NV_PM_ACTION_DEPTH_DEFAULT;
                } else {
                    return -EINVAL;
                }
                return count;
            }
            int nv_procfs_write_suspend(void) {
                status = nv_set_system_power_state(power_state, nv_pm_action_depth);
                return (status != NV_OK) ? -EIO : count;
            }
        """,
        "kernel-open/nvidia/nv-msi.c": """
            int nv_request_msix_irq(void) {
                return request_threaded_irq(entry->vector, nvidia_isr_msix,
                                             nvidia_isr_msix_kthread_bh, flags, name, nvl);
            }
        """,
        "src/nvidia/arch/nvalloc/unix/src/unix_intr.c": """
            static NV_STATUS _rm_gpu_copy_mmu_faults_unlocked(void) {
                return kgmmuCopyMmuFaults_HAL(pGpu, pKernelGmmu, pThreadState,
                                              faultsCopied, NON_REPLAYABLE_FAULT_BUFFER,
                                              NV_FALSE);
            }
            NV_STATUS rm_gpu_handle_mmu_faults(void) {
                if (IS_GSP_CLIENT(pGpu)) {
                    status = NV_OK;
                }
                else {
                    status = _rm_gpu_copy_mmu_faults_unlocked();
                }
                return status;
            }
        """,
        "src/nvidia/arch/nvalloc/unix/src/dynamic-power.c": """
            static NV_STATUS RmPowerManagement(OBJGPU *pGpu, nv_pm_action_t pmAction) {
                switch (pmAction) {
                case NV_PM_ACTION_HIBERNATE:
                    nvp->pm_state.IntrEn = intrGetIntrEn(pIntr);
                    intrSetIntrEn(pIntr, INTERRUPT_TYPE_DISABLED);
                    rmStatus = gpuEnterHibernate(pGpu);
                    break;
                case NV_PM_ACTION_STANDBY:
                    nvp->pm_state.IntrEn = intrGetIntrEn(pIntr);
                    intrSetIntrEn(pIntr, INTERRUPT_TYPE_DISABLED);
                    rmStatus = gpuEnterStandby(pGpu);
                    break;
                case NV_PM_ACTION_RESUME:
                    gpuResumeFromStandby(pGpu);
                    intrSetIntrEn(pIntr, nvp->pm_state.IntrEn);
                    break;
                }
                return rmStatus;
            }
            NV_STATUS rm_power_management(void) {
                rmGpuLocksAcquire(GPUS_LOCK_FLAGS_NONE, owner);
                RmPowerManagement(pGpu, pmAction);
                rmGpuLocksRelease(GPUS_LOCK_FLAGS_NONE, NULL);
                return rmStatus;
            }
        """,
        "src/nvidia/generated/g_kern_gmmu_nvoc.c": """
            // kgmmuCopyMmuFaults -- halified (3 hals) body
            if (( ((rmVariantHal_HalVarIdx >> 5) == 0UL) &&
                  ((1UL << (rmVariantHal_HalVarIdx & 0x1f)) & 0x00000001UL) )) /* RmVariantHal: VF */
            {
                if (( ((chipHal_HalVarIdx >> 5) == 3UL) &&
                      ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0x00005000UL) )) /* ChipHal: T234D | T264D */
                {
                    pThis->__kgmmuCopyMmuFaults__ = &kgmmuCopyMmuFaults_56cd7a;
                }
                else
                {
                    pThis->__kgmmuCopyMmuFaults__ = &kgmmuCopyMmuFaults_GV100;
                }
            }
            else
            {
                pThis->__kgmmuCopyMmuFaults__ = &kgmmuCopyMmuFaults_92bfc3;
            }
            // kgmmuParseFaultPacket -- halified body
            if (chipHal_HalVarIdx == VOLTA_HAL) { next(); }
        """,
        "src/nvidia/src/kernel/gpu/mmu/arch/volta/kern_gmmu_gv100.c": """
            static NV_STATUS _kgmmuCopyFaultPktInShadowBuf_GV100(void) {
                if (bRmServiceable)
                    queuePush(pRmShadowFaultBuf, pFaultPacket, 1);
                else
                    kgmmuCopyFaultPacketToClientShadowBuffer_HAL(pGpu, pKernelGmmu,
                                                                  pFaultBuffer, type, index,
                                                                  put, max, pThreadState,
                                                                  &copiedCount);
                if (!bRmServiceable) {
                    portAtomicMemoryFenceStore();
                    kgmmuWriteClientShadowBufPutIndex_HAL(pGpu, pKernelGmmu,
                                                           GPU_GFID_PF, type, put);
                }
                return NV_OK;
            }
            NvU32 kgmmuCopyFaultPacketToClientShadowBuffer_GV100(void) {
                *pFaultsCopied = queuePushNonManaged(pQueue, &queueContext,
                                                      pFaultPacket, 1);
                return NV_OK;
            }
            NV_STATUS kgmmuCopyMmuFaults_GV100(void) {
                if ((pIntr == NULL) ||
                    (intrGetIntrEn(pIntr) == INTERRUPT_TYPE_DISABLED) ||
                    pKernelGmmu->getProperty(pKernelGmmu, PDB_PROP_KGMMU_FAULT_BUFFER_DISABLED))
                    return NV_OK;
                if (totalCount == 0) {
                    val = pHwFaultBuffer->cachedGetIndex;
                    kgmmuWriteFaultBufferGetPtr_HAL(pGpu, pKernelGmmu, type,
                                                     val, pThreadState);
                    goto done;
                }
                status = _kgmmuCopyFaultPktInShadowBuf_GV100();
                if (status != NV_OK)
                    goto done;
                kgmmuFaultBufferClearPackets_HAL(pGpu, pKernelGmmu, pHwFaultBuffer,
                                                 get, count);
                portAtomicMemoryFenceStore();
                portAtomicSetS32(&pKernelGmmu->mmuFaultBuffer[GPU_GFID_PF].fatalFaultIntrPending, 1);
                portAtomicMemoryFenceStore();
                kgmmuWriteFaultBufferGetPtr_HAL(pGpu, pKernelGmmu, type, nextGet, pThreadState);
            done:
                return status;
            }
            NV_STATUS kgmmuServiceNonReplayableFault_GV100(void) {
                pShadowFaultBuf = pKernelGmmu->mmuFaultBuffer[GPU_GFID_PF].pRmShadowFaultBuffer;
                while (!queueIsEmpty(pShadowFaultBuf)) {
                    queuePopAndCopy(pShadowFaultBuf, &faultPacket);
                    kgmmuHandleNonReplayableFaultPacket_HAL(pGpu, pKernelGmmu,
                                                             &faultPacket);
                }
                return kgmmuNotifyNonReplayableFault_HAL(pGpu, pKernelGmmu,
                                                          bNotifyClient);
            }
        """,
        "kernel-open/nvidia-uvm/uvm_gpu_isr.c": """
            static NV_STATUS uvm_isr_top_half(void) {
                uvm_spin_lock_irqsave(&parent_gpu->isr.interrupts_lock);
                schedule_non_replayable_faults_handler(parent_gpu);
                uvm_spin_unlock_irqrestore(&parent_gpu->isr.interrupts_lock);
                return NV_OK;
            }
        """,
        "kernel-open/nvidia-uvm/uvm_global.c": """
            static void uvm_parent_gpu_set_isr_suspended(void) {
                uvm_spin_lock_irqsave(&parent_gpu->isr.interrupts_lock);
                parent_gpu->isr.is_suspended = true;
                uvm_spin_unlock_irqrestore(&parent_gpu->isr.interrupts_lock);
            }
        """,
    }
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


class R580FaultInterruptAuditTests(unittest.TestCase):
    def test_report_pins_exact_audit_tool_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            report = AUDIT.audit_tree(root)
            tool_path = ROOT / "tools/audit_r580_fault_interrupt_service.py"
            self.assertEqual(report["schema"], "r580-fault-interrupt-service-audit-v9")
            self.assertEqual(report["audit_tool"]["path"], tool_path.name)
            self.assertEqual(report["audit_tool"]["sha256"],
                             hashlib.sha256(tool_path.read_bytes()).hexdigest())

    def test_reports_client_queue_and_all_engine_interrupt_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            report = AUDIT.audit_tree(root)
            facts = report["facts"]
            self.assertTrue(facts["rm_populates_uvm_cpu_client_queue"])
            self.assertTrue(facts["client_queue_apis_do_not_acquire_rm_gpu_locks"])
            self.assertTrue(facts["uvm_rm_method_services_all_engine_interrupts"])
            self.assertTrue(facts["stall_service_loops_over_pending_engines"])
            self.assertTrue(facts["gp100_pending_enumeration_includes_gmmu"])
            self.assertTrue(facts["gmmu_pending_checks_fault_service_state"])
            self.assertTrue(facts["non_gsp_rm_registers_non_replayable_fault_service"])
            self.assertTrue(facts["non_replayable_service_runs_after_hw_top_half"])
            self.assertTrue(facts["control_success_does_not_prove_stuck_interrupt_drained"])
            self.assertTrue(facts["linux_isr_copies_faults_before_uvm_callback"])
            self.assertTrue(facts["non_gsp_fault_handler_invokes_rm_shadow_copy"])
            self.assertTrue(facts[
                "generated_hal_routes_vf_non_t234d_t264d_to_gv100_fault_copy"])
            self.assertTrue(facts["gv100_copy_routes_rm_and_client_faults"])
            self.assertTrue(facts["client_queue_publish_is_fenced_before_put"])
            self.assertTrue(facts[
                "gv100_empty_copy_rewrites_hw_get_without_shadow_publication"])
            self.assertTrue(facts[
                "gv100_nonempty_copy_advances_hw_get_after_shadow_publication"])
            gv100_source = root / (
                "src/nvidia/src/kernel/gpu/mmu/arch/volta/kern_gmmu_gv100.c")
            raw_source = gv100_source.read_text()
            self.assertEqual(
                report["source_lines"]["gv100_empty_hw_buffer_path"],
                raw_source[:raw_source.index("if (totalCount == 0)")].count("\n") + 1)
            self.assertEqual(
                report["ordering_assessment"]["hardware_fault_buffer_paths"][
                    "empty_total_count"],
                "rewrites cached GET and exits without shadow publication")
            self.assertTrue(facts["rm_interrupt_service_consumes_rm_queue_and_notifies"])
            self.assertTrue(facts["uvm_suspend_and_top_half_share_isr_lock"])

    def test_rejects_uvm_callback_moved_before_rm_fault_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "kernel-open/nvidia/nv.c"
            source = path.read_text()
            source = source.replace(
                "rm_gpu_handle_mmu_faults(sp, nv, &faultsCopied);\n"
                "                if (nv_uvm_event_interrupt(uuid) == NV_OK)",
                "if (nv_uvm_event_interrupt(uuid) == NV_OK)", 1)
            source = source.replace(
                "uvm_handled = NV_TRUE;\n"
                "                rm_isr(sp, nv, &need_bottom_half);",
                "uvm_handled = NV_TRUE;\n"
                "                rm_gpu_handle_mmu_faults(sp, nv, &faultsCopied);\n"
                "                rm_isr(sp, nv, &need_bottom_half);", 1)
            path.write_text(source)
            with self.assertRaisesRegex(
                    ValueError, "linux_isr_copies_faults_before_uvm_callback"):
                AUDIT.audit_tree(root)

    def test_rejects_client_queue_publication_without_memory_fence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "src/nvidia/src/kernel/gpu/mmu/arch/volta/kern_gmmu_gv100.c"
            source = path.read_text().replace("portAtomicMemoryFenceStore();", "", 1)
            path.write_text(source)
            with self.assertRaisesRegex(
                    ValueError, "client_queue_publish_is_fenced_before_put"):
                AUDIT.audit_tree(root)

    def test_rejects_gv100_hal_assignment_outside_the_expected_generated_branch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "src/nvidia/generated/g_kern_gmmu_nvoc.c"
            source = path.read_text().replace(
                "&kgmmuCopyMmuFaults_GV100", "&kgmmuCopyMmuFaults_56cd7a", 1)
            path.write_text(source)
            with self.assertRaisesRegex(
                    ValueError,
                    "generated_hal_routes_vf_non_t234d_t264d_to_gv100_fault_copy"):
                AUDIT.audit_tree(root)

    def test_rejects_empty_fault_buffer_path_without_cached_get_rewrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / (
                "src/nvidia/src/kernel/gpu/mmu/arch/volta/kern_gmmu_gv100.c")
            source = path.read_text().replace(
                "kgmmuWriteFaultBufferGetPtr_HAL(pGpu, pKernelGmmu, type,\n"
                "                                                     val, pThreadState);\n",
                "/* omitted cached GET rewrite */\n", 1)
            path.write_text(source)
            with self.assertRaisesRegex(
                    ValueError,
                    "gv100_empty_copy_rewrites_hw_get_without_shadow_publication"):
                AUDIT.audit_tree(root)

    def test_does_not_use_pre_empty_transition_copy_as_nonempty_path_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / (
                "src/nvidia/src/kernel/gpu/mmu/arch/volta/kern_gmmu_gv100.c")
            source = path.read_text()
            copy_call = "                status = _kgmmuCopyFaultPktInShadowBuf_GV100();\n"
            source = source.replace(copy_call, "", 1)
            source = source.replace(
                "                if (totalCount == 0) {",
                copy_call + "                if (totalCount == 0) {", 1)
            path.write_text(source)
            with self.assertRaisesRegex(
                    ValueError,
                    "gv100_nonempty_copy_advances_hw_get_after_shadow_publication"):
                AUDIT.audit_tree(root)

    def test_keeps_copy_completion_race_outside_static_claims(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            report = AUDIT.audit_tree(root)
            self.assertTrue(any(
                "do not establish that suspend waits for an in-flight linux rm interrupt handler"
                in item.lower() for item in report["limitations"]))

    def test_reports_rm_interrupt_mask_separately_from_linux_isr_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            report = AUDIT.audit_tree(root)
            pm = report.get("ordering_assessment", {}).get("pm_irq_quiescence")
            self.assertIsNotNone(pm, "audit must classify the PM IRQ barrier")
            self.assertTrue(pm["procfs_modeset_depth_returns_before_preempt_or_uvm"])
            self.assertTrue(pm["procfs_uvm_depth_returns_after_uvm_before_gpu_suspend"])
            self.assertTrue(pm["procfs_full_depth_orders_preempt_uvm_gpu_suspend"])
            self.assertTrue(pm["rm_disables_intr_state_before_gpu_power_transition"])
            self.assertTrue(pm["intr_setter_only_changes_rm_software_state"])
            self.assertTrue(pm["gv100_fault_copy_checks_rm_intr_state"])
            self.assertTrue(pm["msix_wrapper_serializes_isr_calls"])
            self.assertTrue(pm.get("normal_irq_registered_directly_to_fault_copy_isr"),
                            "legacy IRQ registration must point directly at nvidia_isr")
            self.assertTrue(pm.get("msix_irq_registered_to_serializing_wrapper"),
                            "MSI-X registration must use the serialized wrapper")
            self.assertFalse(pm["pm_wrapper_contains_linux_irq_wait"])
            self.assertFalse(pm["linux_pci_dpm_suspend_calls_global_uvm_suspend"])
            self.assertFalse(pm["in_flight_rm_fault_copy_completion_proven"])

    def test_scopes_procfs_suspend_order_by_action_depth_and_linux_dpm_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            pm = AUDIT.audit_tree(root)["ordering_assessment"]["pm_irq_quiescence"]
            self.assertTrue(pm["procfs_modeset_depth_returns_before_preempt_or_uvm"])
            self.assertTrue(pm["procfs_uvm_depth_returns_after_uvm_before_gpu_suspend"])
            self.assertTrue(pm["procfs_full_depth_orders_preempt_uvm_gpu_suspend"])
            self.assertTrue(pm["linux_pci_dpm_suspend_calls_per_device_suspend"])
            self.assertFalse(pm["linux_pci_dpm_suspend_calls_global_uvm_suspend"])

    def test_rejects_audit_if_uvm_depth_no_longer_returns_before_gpu_suspend(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "kernel-open/nvidia/nv.c"
            source = path.read_text().replace(
                "if (pm_action_depth == NV_PM_ACTION_DEPTH_UVM) {\n"
                "                    return NV_OK;\n"
                "                }",
                "if (pm_action_depth == NV_PM_ACTION_DEPTH_UVM) {\n"
                "                    nv_preempt_user_channels();\n"
                "                }", 1)
            path.write_text(source)
            with self.assertRaisesRegex(
                    ValueError, "procfs_uvm_depth_returns_after_uvm_before_gpu_suspend"):
                AUDIT.audit_tree(root)

    def test_does_not_equate_a_linux_irq_wait_call_with_producer_quiescence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "kernel-open/nvidia/nv.c"
            source = path.read_text().replace(
                "status = rm_power_management(sp, nv, pm_action);",
                "synchronize_irq(nv->interrupt_line);\n"
                "                status = rm_power_management(sp, nv, pm_action);", 1)
            path.write_text(source)
            pm = AUDIT.audit_tree(root)["ordering_assessment"]["pm_irq_quiescence"]
            self.assertEqual(pm["linux_irq_wait_calls_in_inspected_pm_wrappers"],
                             ["synchronize_irq"])
            self.assertTrue(pm["pm_wrapper_contains_linux_irq_wait"])
            self.assertFalse(pm["in_flight_rm_fault_copy_completion_proven"])

    def test_detects_linux_irq_wait_in_the_pci_suspend_callback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "kernel-open/nvidia/nv.c"
            source = path.read_text().replace(
                "return nvidia_suspend(dev, NV_PM_ACTION_STANDBY, NV_FALSE);",
                "synchronize_irq(nv->interrupt_line);\n"
                "                return nvidia_suspend(dev, NV_PM_ACTION_STANDBY, NV_FALSE);",
                1)
            path.write_text(source)
            pm = AUDIT.audit_tree(root)["ordering_assessment"]["pm_irq_quiescence"]
            self.assertEqual(pm["linux_irq_wait_calls_in_inspected_pm_wrappers"],
                             ["synchronize_irq"])
            self.assertTrue(pm["pm_wrapper_contains_linux_irq_wait"])
            self.assertFalse(pm["in_flight_rm_fault_copy_completion_proven"])

    def test_rejects_a_non_software_irq_operation_in_intr_state_setter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "src/nvidia/src/kernel/gpu/intr/intr.c"
            source = path.read_text().replace(
                "pIntr->intrEn0 = intrEn0;",
                "disable_irq(irq);\n                pIntr->intrEn0 = intrEn0;", 1)
            path.write_text(source)
            with self.assertRaisesRegex(
                    ValueError, "intr_setter_only_changes_rm_software_state"):
                AUDIT.audit_tree(root)

    def test_rejects_unary_mutation_in_intr_state_setter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "src/nvidia/src/kernel/gpu/intr/intr.c"
            source = path.read_text().replace(
                "pIntr->intrEn0 = intrEn0;",
                "pIntr->intrEn0++;\n                pIntr->intrEn0 = intrEn0;", 1)
            path.write_text(source)
            with self.assertRaisesRegex(
                    ValueError, "intr_setter_only_changes_rm_software_state"):
                AUDIT.audit_tree(root)

    def test_setter_contract_is_case_sensitive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "src/nvidia/src/kernel/gpu/intr/intr.c"
            source = path.read_text().replace(
                "pIntr->intrEn0 = intrEn0;", "pIntr->intrEN0 = intrEn0;", 1)
            path.write_text(source)
            with self.assertRaisesRegex(
                    ValueError, "intr_setter_only_changes_rm_software_state"):
                AUDIT.audit_tree(root)

    def test_pins_procfs_depth_selection_and_suspend_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            pm = AUDIT.audit_tree(root)["ordering_assessment"]["pm_irq_quiescence"]
            self.assertTrue(pm["procfs_depth_writer_accepts_uvm_modeset_default"])
            self.assertTrue(pm["procfs_suspend_writer_uses_selected_depth"])
            self.assertTrue(pm["procfs_control_functions_have_no_preprocessor_directives"])

    def test_rejects_procfs_suspend_dispatch_that_ignores_selected_depth(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "kernel-open/nvidia/nv-procfs.c"
            source = path.read_text().replace(
                "nv_set_system_power_state(power_state, nv_pm_action_depth)",
                "nv_set_system_power_state(power_state, NV_PM_ACTION_DEPTH_DEFAULT)",
                1)
            path.write_text(source)
            with self.assertRaisesRegex(
                    ValueError, "procfs_suspend_writer_uses_selected_depth"):
                AUDIT.audit_tree(root)

    def test_rejects_procfs_suspend_depth_macro_override(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "kernel-open/nvidia/nv-procfs.c"
            source = path.read_text().replace(
                "status = nv_set_system_power_state(power_state, nv_pm_action_depth);",
                "#define nv_pm_action_depth NV_PM_ACTION_DEPTH_DEFAULT\n"
                "                status = nv_set_system_power_state(power_state, nv_pm_action_depth);\n"
                "#undef nv_pm_action_depth", 1)
            path.write_text(source)
            with self.assertRaisesRegex(
                    ValueError, "procfs_suspend_writer_uses_selected_depth"):
                AUDIT.audit_tree(root)

    def test_rejects_procfs_strcasecmp_macro_override(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "kernel-open/nvidia/nv-procfs.c"
            source = path.read_text().replace(
                '                if (strcasecmp(kbuf, "uvm") == 0) {',
                '#define strcasecmp(a, b) 1\n'
                '                if (strcasecmp(kbuf, "uvm") == 0) {', 1)
            path.write_text(source)
            with self.assertRaisesRegex(
                    ValueError, "procfs_depth_writer_accepts_uvm_modeset_default"):
                AUDIT.audit_tree(root)

    def test_rejects_unconditional_error_after_procfs_depth_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "kernel-open/nvidia/nv-procfs.c"
            source = path.read_text().replace(
                "                return count;\n"
                "            }\n"
                "            int nv_procfs_write_suspend(void)",
                "                return -EINVAL;\n"
                "                return count;\n"
                "            }\n"
                "            int nv_procfs_write_suspend(void)", 1)
            path.write_text(source)
            with self.assertRaisesRegex(
                    ValueError, "procfs_depth_writer_accepts_uvm_modeset_default"):
                AUDIT.audit_tree(root)

    def test_rejects_directive_hidden_by_line_splice(self):
        markers = ("#", "%:", "??=")
        for marker in markers:
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write_source_tree(root)
                path = root / "kernel-open/nvidia/nv-procfs.c"
                directive = (
                    f"{marker}\\\ndefine nv_pm_action_depth "
                    "NV_PM_ACTION_DEPTH_DEFAULT\n")
                undefine = f"{marker}\\\nundef nv_pm_action_depth"
                source = path.read_text().replace(
                    "status = nv_set_system_power_state(power_state, nv_pm_action_depth);",
                    directive +
                    "                status = nv_set_system_power_state(power_state, nv_pm_action_depth);\n"
                    "                " + undefine, 1)
                path.write_text(source)
                with self.assertRaisesRegex(
                        ValueError, "procfs_suspend_writer_uses_selected_depth"):
                    AUDIT.audit_tree(root)

    def test_rejects_directive_after_comment_opener_hidden_by_line_splice(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "kernel-open/nvidia/nv-procfs.c"
            prefix = "                /\\\n* comment */#define nv_pm_action_depth "
            suffix = "                /\\\n* comment */#undef nv_pm_action_depth"
            source = path.read_text().replace(
                "status = nv_set_system_power_state(power_state, nv_pm_action_depth);",
                prefix + "NV_PM_ACTION_DEPTH_DEFAULT\\\n"
                "                status = nv_set_system_power_state(power_state, nv_pm_action_depth);\n"
                + suffix, 1)
            path.write_text(source)
            with self.assertRaisesRegex(
                    ValueError, "procfs_suspend_writer_uses_selected_depth"):
                AUDIT.audit_tree(root)

    def test_rejects_directive_hidden_by_trigraph_splice_and_comment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "kernel-open/nvidia/nv-procfs.c"
            source = path.read_text().replace(
                "status = nv_set_system_power_state(power_state, nv_pm_action_depth);",
                " /??/\n* hidden */#define nv_pm_action_depth "
                "NV_PM_ACTION_DEPTH_DEFAULT\n"
                "                status = nv_set_system_power_state(power_state, nv_pm_action_depth);\n"
                " /??/\n* hidden */#undef nv_pm_action_depth", 1)
            path.write_text(source)
            with self.assertRaisesRegex(
                    ValueError, "procfs_suspend_writer_uses_selected_depth"):
                AUDIT.audit_tree(root)

    def test_rejects_macro_override_in_bare_cr_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "kernel-open/nvidia/nv-procfs.c"
            source = path.read_bytes().replace(b"\n", b"\r")
            source = source.replace(
                b"status = nv_set_system_power_state(power_state, nv_pm_action_depth);",
                b"#define nv_pm_action_depth NV_PM_ACTION_DEPTH_DEFAULT\r"
                b"                status = nv_set_system_power_state(power_state, nv_pm_action_depth);\r"
                b"                #undef nv_pm_action_depth", 1)
            path.write_bytes(source)
            with self.assertRaisesRegex(
                    ValueError, "procfs_suspend_writer_uses_selected_depth"):
                AUDIT.audit_tree(root)

    def test_translates_all_c_trigraphs_before_line_splicing(self):
        translated, offsets = AUDIT._translate_c_trigraphs_with_offsets(
            "??=??/??'??(??)??!??<??>??-")
        self.assertEqual(translated, "#\\^[]|{}~")
        self.assertEqual(offsets, list(range(0, 27, 3)))

    def test_normalizes_crlf_and_bare_cr_with_original_offsets(self):
        translated, offsets = AUDIT._translate_c_trigraphs_with_offsets(
            "a\r\nb\rc\n")
        self.assertEqual(translated, "a\nb\nc\n")
        self.assertEqual(offsets, [0, 1, 3, 4, 5, 6])

    def test_reports_raw_procfs_lines_after_bare_cr_normalization(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "kernel-open/nvidia/nv-procfs.c"
            expected = AUDIT.audit_tree(root)["source_lines"]["procfs_depth_writer"]
            path.write_bytes(path.read_bytes().replace(b"\n", b"\r"))
            report = AUDIT.audit_tree(root)
            self.assertEqual(report["source_lines"]["procfs_depth_writer"], expected)

    def test_rejects_conditional_success_return_followed_by_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "kernel-open/nvidia/nv-procfs.c"
            source = path.read_text().replace(
                "                return count;\n"
                "            }\n"
                "            int nv_procfs_write_suspend(void)",
                "                if (0) return count;\n"
                "                return -EINVAL;\n"
                "                return count;\n"
                "            }\n"
                "            int nv_procfs_write_suspend(void)", 1)
            path.write_text(source)
            with self.assertRaisesRegex(
                    ValueError, "procfs_depth_writer_accepts_uvm_modeset_default"):
                AUDIT.audit_tree(root)

    def test_rejects_unreachable_procfs_depth_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "kernel-open/nvidia/nv-procfs.c"
            source = path.read_text().replace(
                'if (strcasecmp(kbuf, "uvm") == 0) {',
                'return -EINVAL;\n                if (strcasecmp(kbuf, "uvm") == 0) {', 1)
            path.write_text(source)
            with self.assertRaisesRegex(
                    ValueError, "procfs_depth_writer_accepts_uvm_modeset_default"):
                AUDIT.audit_tree(root)

    def test_rejects_unreachable_procfs_suspend_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "kernel-open/nvidia/nv-procfs.c"
            source = path.read_text().replace(
                "status = nv_set_system_power_state(power_state, nv_pm_action_depth);",
                "return -EINVAL;\n"
                "                status = nv_set_system_power_state(power_state, nv_pm_action_depth);",
                1)
            path.write_text(source)
            with self.assertRaisesRegex(
                    ValueError, "procfs_suspend_writer_uses_selected_depth"):
                AUDIT.audit_tree(root)

    def test_rejects_procfs_depth_selection_inside_if_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "kernel-open/nvidia/nv-procfs.c"
            source = path.read_text().replace(
                '                if (strcasecmp(kbuf, "uvm") == 0) {',
                '#if 0\n                if (strcasecmp(kbuf, "uvm") == 0) {', 1)
            source = source.replace(
                "                return count;\n"
                "            }\n"
                "            int nv_procfs_write_suspend(void)",
                "#endif\n"
                "                return -EINVAL;\n"
                "                return count;\n"
                "            }\n"
                "            int nv_procfs_write_suspend(void)", 1)
            path.write_text(source)
            with self.assertRaisesRegex(
                    ValueError, "procfs_depth_writer_accepts_uvm_modeset_default"):
                AUDIT.audit_tree(root)

    def test_rejects_procfs_suspend_call_inside_if_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "kernel-open/nvidia/nv-procfs.c"
            source = path.read_text().replace(
                "status = nv_set_system_power_state(power_state, nv_pm_action_depth);",
                "#if 0\n"
                "                status = nv_set_system_power_state(power_state, nv_pm_action_depth);\n"
                "#endif\n"
                "                return -EINVAL;", 1)
            path.write_text(source)
            with self.assertRaisesRegex(
                    ValueError, "procfs_suspend_writer_uses_selected_depth"):
                AUDIT.audit_tree(root)

    def test_source_hash_preserves_procfs_line_ending_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "kernel-open/nvidia/nv-procfs.c"
            original = AUDIT.audit_tree(root)["source_files"][
                "kernel-open/nvidia/nv-procfs.c"]["sha256"]
            path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
            changed_bytes = path.read_bytes()
            report = AUDIT.audit_tree(root)
            expected = hashlib.sha256(changed_bytes).hexdigest()
            self.assertNotEqual(original, expected)
            self.assertEqual(report["source_files"][
                "kernel-open/nvidia/nv-procfs.c"]["sha256"], expected)

    def test_rejects_rm_power_transition_before_interrupt_state_is_disabled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "src/nvidia/arch/nvalloc/unix/src/dynamic-power.c"
            source = path.read_text().replace(
                "intrSetIntrEn(pIntr, INTERRUPT_TYPE_DISABLED);\n"
                "                    rmStatus = gpuEnterStandby(pGpu);",
                "rmStatus = gpuEnterStandby(pGpu);\n"
                "                    intrSetIntrEn(pIntr, INTERRUPT_TYPE_DISABLED);", 1)
            path.write_text(source)
            with self.assertRaisesRegex(
                    ValueError, "rm_disables_intr_state_before_gpu_power_transition"):
                AUDIT.audit_tree(root)

    def test_rejects_unexpected_interrupt_control_id(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root, method_id="0x20801703")
            with self.assertRaisesRegex(ValueError, "control ID"):
                AUDIT.audit_tree(root)

    def test_rejects_service_limited_to_graphics_instead_of_all_engines(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            path = root / "src/nvidia/src/kernel/rmapi/nv_gpu_ops.c"
            source = path.read_text().replace(
                "params.engines = NV2080_CTRL_MC_ENGINE_ID_ALL;",
                "params.engines = NV2080_CTRL_MC_ENGINE_ID_GRAPHICS;", 1)
            path.write_text(source)
            with self.assertRaisesRegex(
                    ValueError, "uvm_rm_method_services_all_engine_interrupts"):
                AUDIT.audit_tree(root)

    def test_report_marks_service_loop_stuck_exit_as_limited_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            report = AUDIT.audit_tree(root)
            self.assertEqual(report["qualification"], "static-source-contract-only")
            self.assertIn("stuck", report["limitations"][0].lower())

    def test_rejects_audit_when_stuck_interrupt_exit_contract_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root, report_stuck=False)
            with self.assertRaisesRegex(
                    ValueError, "control_success_does_not_prove_stuck_interrupt_drained"):
                AUDIT.audit_tree(root)


if __name__ == "__main__":
    unittest.main()
