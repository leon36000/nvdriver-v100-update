#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit and qualify the opt-in R580 PMM retry outside VA-block lock."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_hybrid_uvm_abi import c_function_definition  # noqa: E402
from tools.audit_uvm_owner_isolation_architecture import (  # noqa: E402
    EXPECTED_ARCHIVE_SHA256,
    SOURCE_ARCHIVE,
    SOURCE_TAG,
)
from tools.probe_r615_gv100_dispatch import write_private_evidence_report  # noqa: E402
from tools.probe_r580_uvm_isolated_execution import PATCHES, project_path  # noqa: E402


SOURCE_ROOT = (
    ROOT
    / "build/experiments/r580-uvm-pmm-retry-pair-v4-20261028T1337Z"
    / "NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm"
)
BUILD_REPORT = ROOT / "evidence/r580-uvm-pmm-retry-pair-v4-20261028T1337Z.json"
SOURCE_FILES = (
    "uvm_gpu.c",
    "uvm_channel.c",
    "uvm_channel.h",
    "uvm_common.c",
    "uvm_gpu_semaphore.c",
    "uvm_push.c",
    "uvm_pmm_gpu.c",
    "uvm_migrate.c",
    "uvm_va_block.h",
    "uvm_va_block.c",
    "uvm_tracker.c",
    "uvm_hmm.c",
    "uvm_gpu_replayable_faults.c",
    "uvm_gpu_non_replayable_faults.c",
    "uvm_gpu_access_counters.c",
)
ISOLATION_PATCH = next(
    path for path in PATCHES if path.name == "0007-reject-cross-gpu-tracker-dependencies.patch"
)
PMM_RETRY_PATCH = next(
    path for path in PATCHES if path.name == "0008-pmm-allocation-outside-va-block-lock.patch"
)
HMM_ISOLATION_PATCH = next(
    path for path in PATCHES
    if path.name == "0009-reject-hmm-gpu-migration-in-isolated-mode.patch"
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def analyze_sources(source_root: Path) -> dict[str, Any]:
    source_root = Path(source_root)
    pmm = c_function_definition(source_root / "uvm_pmm_gpu.c", "pmm_gpu_alloc")
    block_alloc = c_function_definition(source_root / "uvm_va_block.c", "block_alloc_gpu_chunk")
    block_populate = c_function_definition(
        source_root / "uvm_va_block.c", "block_populate_gpu_chunk"
    )
    migrate_map = c_function_definition(
        source_root / "uvm_va_block.c", "uvm_va_block_add_mappings_after_migration"
    )
    migrate_loop = c_function_definition(
        source_root / "uvm_va_block.c", "do_block_add_mappings_after_migration"
    )
    gpu_map = c_function_definition(source_root / "uvm_va_block.c", "block_map_gpu_to")
    migrate_caller = c_function_definition(
        source_root / "uvm_migrate.c", "block_migrate_map_unmapped_pages"
    )
    migration_retry_caller = c_function_definition(
        source_root / "uvm_migrate.c", "uvm_va_range_migrate_multi_block"
    )
    migrate_dispatch = c_function_definition(
        source_root / "uvm_migrate.c", "uvm_va_block_migrate_locked"
    )
    service_dispatch = c_function_definition(
        source_root / "uvm_va_block.c", "uvm_va_block_service_locked"
    )
    va_block_header = (source_root / "uvm_va_block.h").read_text(encoding="utf-8")
    retry_macro_start = va_block_header.find("#define UVM_VA_BLOCK_LOCK_RETRY(")
    retry_macro_end = va_block_header.find("#define UVM_VA_BLOCK_RETRY_LOCKED(", retry_macro_start)
    retry_macro = (
        va_block_header[retry_macro_start:retry_macro_end]
        if retry_macro_start >= 0 and retry_macro_end > retry_macro_start else ""
    )
    tracker_wait = c_function_definition(
        source_root / "uvm_tracker.c", "uvm_tracker_wait_for_other_gpus"
    )
    tracker_entry_completed = c_function_definition(
        source_root / "uvm_tracker.c", "uvm_tracker_is_entry_completed"
    )
    tracker_entry_wait = c_function_definition(
        source_root / "uvm_tracker.c", "wait_for_entry_with_spin"
    )
    channel_value_completed = c_function_definition(
        source_root / "uvm_channel.c", "uvm_channel_is_value_completed"
    )
    semaphore_value_completed = c_function_definition(
        source_root / "uvm_gpu_semaphore.c", "uvm_gpu_tracking_semaphore_is_value_completed"
    )
    semaphore_update = c_function_definition(
        source_root / "uvm_gpu_semaphore.c", "update_completed_value_locked"
    )
    semaphore_payload = c_function_definition(
        source_root / "uvm_gpu_semaphore.c", "uvm_gpu_semaphore_get_payload"
    )
    semaphore_cpu_va = c_function_definition(
        source_root / "uvm_gpu_semaphore.c", "uvm_gpu_semaphore_get_cpu_va"
    )
    semaphore_pool_create = c_function_definition(
        source_root / "uvm_gpu_semaphore.c", "uvm_gpu_semaphore_pool_create"
    )
    semaphore_page_alloc = c_function_definition(
        source_root / "uvm_gpu_semaphore.c", "pool_page_alloc_buffers"
    )
    tracking_semaphore_alloc = c_function_definition(
        source_root / "uvm_gpu_semaphore.c", "uvm_gpu_tracking_semaphore_alloc"
    )
    tracking_semaphore_owner = c_function_definition(
        source_root / "uvm_gpu_semaphore.c", "tracking_semaphore_check_gpu"
    )
    channel_create = c_function_definition(source_root / "uvm_channel.c", "channel_create")
    channel_destroy = c_function_definition(source_root / "uvm_channel.c", "channel_destroy")
    channel_pool_destroy = c_function_definition(
        source_root / "uvm_channel.c", "channel_pool_destroy"
    )
    channel_manager_destroy_pools = c_function_definition(
        source_root / "uvm_channel.c", "channel_manager_destroy_pools"
    )
    channel_manager_destroy = c_function_definition(
        source_root / "uvm_channel.c", "uvm_channel_manager_destroy"
    )
    gpu_init_semaphore_pools = c_function_definition(
        source_root / "uvm_gpu.c", "init_semaphore_pools"
    )
    gpu_deinit_semaphore_pools = c_function_definition(
        source_root / "uvm_gpu.c", "deinit_semaphore_pools"
    )
    gpu_deinit = c_function_definition(source_root / "uvm_gpu.c", "deinit_gpu")
    allow_dependencies = c_function_definition(
        source_root / "uvm_push.c", "uvm_push_allow_dependencies_across_gpus"
    )
    tracker_entry_gpu = c_function_definition(source_root / "uvm_tracker.c", "uvm_tracker_entry_gpu")
    channel_header = (source_root / "uvm_channel.h").read_text(encoding="utf-8")
    spin_loop = c_function_definition(source_root / "uvm_common.c", "uvm_spin_loop")
    hmm_gpu_fault_service = c_function_definition(
        source_root / "uvm_hmm.c", "uvm_hmm_va_block_service_locked"
    )
    hmm_migrate_locked = c_function_definition(
        source_root / "uvm_hmm.c", "uvm_hmm_va_block_migrate_locked"
    )
    hmm_migrate_range = c_function_definition(source_root / "uvm_hmm.c", "hmm_migrate_range")
    replayable_fault_retry = c_function_definition(
        source_root / "uvm_gpu_replayable_faults.c", "service_fault_batch_block"
    )
    replayable_fault_locked = c_function_definition(
        source_root / "uvm_gpu_replayable_faults.c", "service_fault_batch_block_locked"
    )
    non_replayable_fault_retry = c_function_definition(
        source_root / "uvm_gpu_non_replayable_faults.c", "service_managed_fault_in_block"
    )
    non_replayable_fault_locked = c_function_definition(
        source_root / "uvm_gpu_non_replayable_faults.c", "service_managed_fault_in_block_locked"
    )
    access_counter_retry = c_function_definition(
        source_root / "uvm_gpu_access_counters.c", "service_notification_va_block_helper"
    )
    access_counter_locked = c_function_definition(
        source_root / "uvm_gpu_access_counters.c", "service_va_block_locked"
    )
    cpu_fault_retry = c_function_definition(source_root / "uvm_va_block.c", "uvm_va_block_cpu_fault")
    cpu_fault_locked = c_function_definition(source_root / "uvm_va_block.c", "block_cpu_fault_locked")

    pmm_snapshot = "uvm_tracker_add_tracker_safe(&local_tracker, &root_chunk->tracker)"
    pmm_wait = "uvm_tracker_wait_for_other_gpus(&local_tracker, gpu)"
    no_evict_alloc = "uvm_pmm_gpu_alloc_user(&gpu->pmm, 1, size, UVM_PMM_ALLOC_FLAGS_NONE"
    eviction_unlock = "uvm_mutex_unlock(&block->lock)"
    eviction_alloc = "uvm_pmm_gpu_alloc_user(&gpu->pmm, 1, size, UVM_PMM_ALLOC_FLAGS_EVICT"
    lock_assert = "uvm_assert_mutex_locked(&block->lock)"
    chunk_alloc_call = "block_alloc_gpu_chunk(block, retry, gpu, chunk_size, &chunk)"

    pmm_snapshot_index = pmm.find(pmm_snapshot)
    pmm_wait_index = pmm.find(pmm_wait)
    isolated_start = block_alloc.find("if (uvm_push_isolated_gpu_execution_enabled())")
    isolated_end = block_alloc.find("} else {", isolated_start)
    isolated_branch = block_alloc[isolated_start:isolated_end] if isolated_start >= 0 and isolated_end >= 0 else ""
    default_branch_start = isolated_end + len("} else {") if isolated_end >= 0 else -1
    default_branch_end = block_alloc.find("}", default_branch_start) if default_branch_start >= 0 else -1
    default_branch = block_alloc[default_branch_start:default_branch_end] if default_branch_end >= 0 else ""
    isolated_unlock_index = isolated_branch.find(eviction_unlock)
    isolated_alloc_index = isolated_branch.find(no_evict_alloc)
    isolated_success_index = isolated_branch.find("if (status == NV_OK)")
    isolated_requeue_index = isolated_branch.find("block_retry_add_free_chunk(retry, gpu_chunk)", isolated_success_index)
    isolated_restart_index = isolated_branch.find("status = NV_ERR_MORE_PROCESSING_REQUIRED", isolated_requeue_index)
    isolated_relock_index = isolated_branch.find("uvm_mutex_lock(&block->lock)", isolated_restart_index)
    isolated_error_gate_index = isolated_branch.find("if (status != NV_ERR_NO_MEMORY)", isolated_relock_index)
    no_memory_gate_index = block_alloc.find("if (status == NV_ERR_NO_MEMORY)")
    eviction_alloc_index = block_alloc.find(eviction_alloc, no_memory_gate_index)
    # There are now two unlock sites in this function. Search only within the
    # eviction branch so the opt-in no-eviction unlock cannot satisfy it.
    eviction_unlock_index = (
        block_alloc.find(eviction_unlock, no_memory_gate_index)
        if no_memory_gate_index >= 0 else -1
    )
    hmm_gpu_prealloc_index = hmm_gpu_fault_service.find("uvm_va_block_populate_pages_gpu(")
    hmm_gpu_setup_index = hmm_gpu_fault_service.find("migrate_vma_setup_locked(")
    hmm_migrate_prealloc_index = hmm_migrate_locked.find("uvm_va_block_populate_pages_gpu(")
    hmm_migrate_setup_index = hmm_migrate_locked.find("migrate_vma_setup_locked(")
    hmm_gpu_prealloc_error = hmm_gpu_fault_service.find("if (status != NV_OK)", hmm_gpu_prealloc_index)
    hmm_gpu_prealloc_return = hmm_gpu_fault_service.find("return status;", hmm_gpu_prealloc_error)
    hmm_migrate_prealloc_error = hmm_migrate_locked.find("if (status != NV_OK)", hmm_migrate_prealloc_index)
    hmm_migrate_prealloc_return = hmm_migrate_locked.find("return status;", hmm_migrate_prealloc_error)
    # c_function_definition normalizes whitespace and masks comments, so keep
    # these predicates independent of source indentation and line wrapping.
    hmm_gpu_guard = "if (uvm_push_isolated_gpu_execution_enabled()) return NV_ERR_NOT_SUPPORTED;"
    hmm_migrate_guard = (
        "if (uvm_push_isolated_gpu_execution_enabled() && UVM_ID_IS_GPU(dest_id)) "
        "return NV_ERR_NOT_SUPPORTED;"
    )
    hmm_gpu_guard_index = hmm_gpu_fault_service.find(hmm_gpu_guard)
    hmm_gpu_cpu_fallback_index = hmm_gpu_fault_service.find(
        "return hmm_block_cpu_fault_locked(processor_id, va_block, va_block_retry, service_context);"
    )
    hmm_migrate_guard_index = hmm_migrate_locked.find(hmm_migrate_guard)
    hmm_migrate_sysmem_fallback_index = hmm_migrate_locked.find(
        "if (UVM_ID_IS_GPU(dest_id) && uvm_hmm_must_use_sysmem(va_block, vma))"
    )
    checks = {
        "pmm_alloc_waits_for_foreign_gpu_tracker": pmm_wait_index >= 0,
        "pmm_wait_follows_root_tracker_collection": (
            pmm_snapshot_index >= 0 and pmm_wait_index > pmm_snapshot_index
        ),
        "block_population_asserts_va_block_lock": (
            block_populate.find(lock_assert) >= 0
            and block_populate.find(chunk_alloc_call) > block_populate.find(lock_assert)
        ),
        "isolated_no_evict_alloc_releases_block_lock": (
            isolated_start >= 0 and isolated_end > isolated_start
            and isolated_unlock_index >= 0
            and isolated_alloc_index > isolated_unlock_index
            and isolated_relock_index > isolated_alloc_index
            and isolated_error_gate_index > isolated_relock_index
        ),
        "isolated_success_requeues_chunk_and_restarts": (
            isolated_success_index >= 0
            and isolated_requeue_index > isolated_success_index
            and isolated_restart_index > isolated_requeue_index
            and isolated_relock_index > isolated_restart_index
        ),
        "default_no_evict_alloc_is_unchanged": (
            default_branch_start >= 0 and default_branch_end > default_branch_start
            and no_evict_alloc in default_branch
            and eviction_unlock not in default_branch
        ),
        "eviction_retry_releases_lock_before_pmm_alloc": (
            eviction_unlock_index >= 0
            and eviction_alloc_index > eviction_unlock_index
        ),
        "lock_retry_macro_repeats_more_processing": (
            "__status = (call);" in retry_macro
            and "} while (__status == NV_ERR_MORE_PROCESSING_REQUIRED);" in retry_macro
        ),
        "migration_make_resident_uses_lock_retry": (
            "UVM_VA_BLOCK_LOCK_RETRY(" in migration_retry_caller
            and "uvm_va_block_migrate_locked(" in migration_retry_caller
        ),
        "hmm_gpu_fault_preallocation_precedes_migrate_vma_setup": (
            hmm_gpu_prealloc_index >= 0
            and hmm_gpu_setup_index > hmm_gpu_prealloc_index
            and hmm_gpu_prealloc_error > hmm_gpu_prealloc_index
            and hmm_gpu_prealloc_return > hmm_gpu_prealloc_error
            and hmm_gpu_prealloc_return < hmm_gpu_setup_index
        ),
        "hmm_migration_preallocation_precedes_migrate_vma_setup": (
            hmm_migrate_prealloc_index >= 0
            and hmm_migrate_setup_index > hmm_migrate_prealloc_index
            and hmm_migrate_prealloc_error > hmm_migrate_prealloc_index
            and hmm_migrate_prealloc_return > hmm_migrate_prealloc_error
            and hmm_migrate_prealloc_return < hmm_migrate_setup_index
        ),
        "isolated_hmm_gpu_fault_fails_closed_after_cpu_fault_path": (
            hmm_gpu_guard_index >= 0
            and hmm_gpu_cpu_fallback_index >= 0
            and hmm_gpu_guard_index > hmm_gpu_cpu_fallback_index
            and hmm_gpu_prealloc_index > hmm_gpu_guard_index
            and hmm_gpu_setup_index > hmm_gpu_guard_index
        ),
        "isolated_hmm_gpu_migration_fails_closed_after_sysmem_fallback": (
            hmm_migrate_guard_index >= 0
            and hmm_migrate_sysmem_fallback_index >= 0
            and hmm_migrate_guard_index > hmm_migrate_sysmem_fallback_index
            and hmm_migrate_prealloc_index > hmm_migrate_guard_index
            and hmm_migrate_setup_index > hmm_migrate_guard_index
        ),
        "hmm_gpu_fault_retry_is_wrapped_by_va_block_retry": (
            "uvm_hmm_va_block_service_locked(" in service_dispatch
            and "uvm_va_block_service_locked(" in replayable_fault_locked
            and "UVM_VA_BLOCK_RETRY_LOCKED(" in replayable_fault_retry
            and "service_fault_batch_block_locked(" in replayable_fault_retry
            and "uvm_va_block_service_locked(" in non_replayable_fault_locked
            and "UVM_VA_BLOCK_RETRY_LOCKED(" in non_replayable_fault_retry
            and "service_managed_fault_in_block_locked(" in non_replayable_fault_retry
        ),
        "hmm_migration_retry_is_wrapped_by_va_block_retry": (
            "UVM_VA_BLOCK_RETRY_LOCKED(" in hmm_migrate_range
            and "uvm_va_block_migrate_locked(" in hmm_migrate_range
            and "uvm_hmm_va_block_migrate_locked(" in migrate_dispatch
        ),
        "fault_service_retry_paths_are_va_block_wrapped": (
            "uvm_va_block_service_locked(" in cpu_fault_locked
            and "UVM_VA_BLOCK_LOCK_RETRY(" in cpu_fault_retry
            and "block_cpu_fault_locked(" in cpu_fault_retry
            and "uvm_va_block_service_locked(" in replayable_fault_locked
            and "UVM_VA_BLOCK_RETRY_LOCKED(" in replayable_fault_retry
            and "service_fault_batch_block_locked(" in replayable_fault_retry
            and "uvm_va_block_service_locked(" in non_replayable_fault_locked
            and "UVM_VA_BLOCK_RETRY_LOCKED(" in non_replayable_fault_retry
            and "service_managed_fault_in_block_locked(" in non_replayable_fault_retry
            and "uvm_va_block_service_locked(" in access_counter_locked
            and "UVM_VA_BLOCK_RETRY_LOCKED(" in access_counter_retry
            and "service_va_block_locked(" in access_counter_retry
        ),
        "tracker_wait_polls_channel_tracking_semaphore": (
            "uvm_tracker_is_entry_completed(tracker_entry)" in tracker_entry_wait
            and "wait_for_entry_with_spin(entry, &spin)" in tracker_wait
            and "uvm_channel_is_value_completed(tracker_entry->channel, tracker_entry->value)" in tracker_entry_completed
            and "uvm_gpu_tracking_semaphore_is_value_completed(&channel->tracking_sem, value)" in channel_value_completed
            and "uvm_gpu_tracking_semaphore_update_completed_value(tracking_sem)" in semaphore_value_completed
        ),
        "channel_completion_refreshes_from_cpu_mapped_payload": (
            "uvm_gpu_semaphore_get_payload(&tracking_semaphore->semaphore)" in semaphore_update
            and "UVM_GPU_READ_ONCE(*uvm_gpu_semaphore_get_cpu_va(semaphore))" in semaphore_payload
        ),
        "spin_loop_schedules_for_rm_uvm_progress": (
            "UVM_SPIN_LOOP_SCHEDULE_TIMEOUT_NS" in spin_loop
            and "NV_MAY_SLEEP()" in spin_loop
            and "schedule();" in spin_loop
            and "UVM_SPIN_LOOP_SCHEDULE_TIMEOUT_NS   (10*1000ULL)" in
                (source_root / "uvm_common.c").read_text(encoding="utf-8")
            and "This schedule() is required for functionality" in
                (source_root / "uvm_common.c").read_text(encoding="utf-8")
        ),
        "tracker_wait_timeout_is_warning_only": (
            "if (UVM_SPIN_LOOP(spin) == NV_ERR_TIMEOUT_RETRY)" in tracker_entry_wait
            and "return NV_ERR_TIMEOUT_RETRY" not in tracker_entry_wait
            and "UVM_SPIN_LOOP_PRINT_TIMEOUT_SEC     30ULL" in
                (source_root / "uvm_common.c").read_text(encoding="utf-8")
        ),
        "wait_uses_cpu_spin_entry_helper": (
            "wait_for_entry_with_spin(entry, &spin)" in tracker_wait
        ),
        "migration_selects_accessed_by_processors": (
            "uvm_processor_mask_copy(map_other_processors, &policy->accessed_by)" in migrate_map
            and "va_space->accessible_from[uvm_id_value(new_residency)]" in migrate_map
        ),
        "multiple_gpu_maps_accumulate_in_local_output_tracker": (
            "for_each_id_in_mask(map_processor_id, map_processors_local)" in migrate_loop
            and "uvm_va_block_map(" in migrate_loop
            and "&local_tracker" in migrate_map
        ),
        "gpu_map_acquires_global_tracker_but_appends_to_output": (
            "uvm_push_begin_acquire(" in gpu_map
            and "&va_block->tracker" in gpu_map
            and "uvm_tracker_add_push_safe(out_tracker, &push)" in gpu_map
        ),
        "migration_merges_local_tracker_into_va_block_tracker": (
            "uvm_va_block_add_mappings_after_migration(" in migrate_caller
            and "&local_tracker" in migrate_caller
            and "uvm_tracker_add_tracker_safe(&va_block->tracker, &local_tracker)" in migrate_caller
        ),
        "pmm_free_imports_va_block_tracker": (
            "uvm_pmm_gpu_free(&gpu->pmm, chunk, &block->tracker)" in block_populate
        ),
        "tracking_semaphore_uses_channel_gpu_owned_pool": (
            "pool->gpu = gpu" in semaphore_pool_create
            and "uvm_gpu_semaphore_alloc(pool, &tracking_sem->semaphore)" in tracking_semaphore_alloc
            and "uvm_gpu_t *gpu = manager->gpu" in channel_create
            and "uvm_gpu_semaphore_pool_t *semaphore_pool = gpu->semaphore_pool" in channel_create
            and "uvm_gpu_tracking_semaphore_alloc(semaphore_pool, &channel->tracking_sem)" in channel_create
            and "uvm_gpu_tracking_semaphore_t tracking_sem" in channel_header
            and "tracking_sem->semaphore.page->pool->gpu" in tracking_semaphore_owner
            and "table_gpu == gpu" in tracking_semaphore_owner
            and "return uvm_channel_get_gpu(entry->channel)" in tracker_entry_gpu
            and "return channel->pool->manager->gpu" in channel_header
        ),
        "isolated_owner_semaphore_page_is_cpu_mapped_and_cross_gpu_mapping_is_skipped": (
            "pool->gpu = gpu" in semaphore_pool_create
            and "UVM_RM_MEM_TYPE_SYS" in semaphore_page_alloc
            and "uvm_rm_mem_alloc_and_map_cpu" in semaphore_page_alloc
            and "uvm_gpu_semaphore_get_cpu_va" in semaphore_payload
            and "uvm_rm_mem_get_cpu_va(semaphore->page->memory)" in semaphore_cpu_va
            and "!uvm_push_allow_dependencies_across_gpus()" in gpu_init_semaphore_pools
            and "return NV_OK" in gpu_init_semaphore_pools
            and "uvm_gpu_semaphore_pool_map_gpu(other_gpu->semaphore_pool, gpu)" in gpu_init_semaphore_pools
            and "!g_uvm_global.conf_computing_enabled && !uvm_hybrid_isolated_gpu_execution" in allow_dependencies
            and "uvm_gpu_semaphore_pool_unmap_gpu(other_gpu->semaphore_pool, gpu)" in gpu_deinit_semaphore_pools
        ),
        "channel_tracking_semaphore_released_after_progress_and_rm_channel": (
            channel_destroy.find("channel_update_progress_all(channel, UVM_CHANNEL_UPDATE_MODE_FORCE_ALL)") >= 0
            and channel_destroy.find("nvUvmInterfaceChannelDestroy(channel->handle)") >
                channel_destroy.find("channel_update_progress_all(channel, UVM_CHANNEL_UPDATE_MODE_FORCE_ALL)")
            and channel_destroy.find("uvm_gpu_tracking_semaphore_free(&channel->tracking_sem)") >
                channel_destroy.find("nvUvmInterfaceChannelDestroy(channel->handle)")
            and "channel_destroy(pool, pool->channels + pool->num_channels - 1)" in channel_pool_destroy
            and "channel_pool_destroy(manager->channel_pools + manager->num_channel_pools - 1)" in channel_manager_destroy_pools
            and "channel_manager_destroy_pools(channel_manager)" in channel_manager_destroy
        ),
        "gpu_teardown_removes_tracker_references_and_syncs_before_semaphore_pool_free": (
            gpu_deinit.find("remove_gpus_from_gpu(other_gpu)") >= 0
            and gpu_deinit.find("remove_gpu_from_parent_gpu(gpu)") >
                gpu_deinit.find("remove_gpus_from_gpu(other_gpu)")
            and gpu_deinit.find("uvm_pmm_gpu_sync(&gpu->pmm)") >
                gpu_deinit.find("remove_gpu_from_parent_gpu(gpu)")
            and gpu_deinit.find("uvm_channel_manager_destroy(gpu->channel_manager)") >
                gpu_deinit.find("uvm_pmm_gpu_sync(&gpu->pmm)")
            and gpu_deinit.find("deinit_semaphore_pools(gpu)") >
                gpu_deinit.find("uvm_channel_manager_destroy(gpu->channel_manager)")
            and "uvm_gpu_semaphore_pool_destroy(gpu->semaphore_pool)" in gpu_deinit_semaphore_pools
        ),
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    return {
        "status": "conditionally_mitigated" if not failed else "unresolved",
        "checks": checks,
        "failed_checks": failed,
        "interpretation": (
            "The pinned R580 source gives a conditional route for a foreign tracker into the PMM "
            "wait. Migration can merge mapping pushes from multiple accessible GPU IDs into the "
            "VA-block tracker; block cleanup can then pass that tracker into the PMM root tracker. "
            "The opt-in patch now unlocks the VA block around ordinary no-eviction PMM allocation, "
            "retains a successful chunk on the retry list, reacquires the lock, and forces the "
            "caller to restart and revalidate. The stock/default allocation path remains unchanged. "
            "The HMM paths preallocate GPU chunks before migrate_vma_setup_locked can page-lock source pages, "
            "and the fault, access-counter, CPU-fault, and migration entry points wrap the retry status "
            "in VA-block retry loops. This source ordering avoids introducing this PMM unlock after HMM "
            "page locking, but does not prove runtime race freedom. The opt-in HMM guard now "
            "keeps CPU HMM faults and CPU/system-memory fallbacks available while returning "
            "NV_ERR_NOT_SUPPORTED for HMM GPU faults and GPU-destination HMM migrations before "
            "GPU-page population or migrate_vma page locking. This deliberately disables those "
            "GPU-resident HMM paths in isolated mode; it is not a general UVM compatibility claim. "
            "Thus the specific foreign-tracker wait is statically shown to be unlocked in isolated "
            "mode, while the conditional source route still exists. The wait polls a channel's GPU "
            "tracking semaphore through its CPU mapping and refreshes the cached value by reading "
            "the mapped payload. In sleepable context, the spin helper schedules after about 10 us; "
            "the source comment says this is required for RM interrupts and UVM fault service. The "
            "30-second warning is diagnostic only, not a wait deadline. This is not proof of a "
            "deadlock or of safe cross-provider completion: source shows tracker entries resolve "
            "through their channel to a GPU-owned semaphore pool, and isolated mode skips peer "
            "GPU semaphore mappings while rejecting cross-GPU dependencies. Teardown removes "
            "tracker references, synchronizes PMM, destroys channels and then semaphore pools. "
            "These source-order checks do not prove runtime completion, CPU visibility/coherence, "
            "or absence of races. Provider-affine memory duplication still rejects cross-provider "
            "operations, and mixed-provider UVM address-space/runtime behavior remains unvalidated."
        ),
    }


def audit_sources(source_root: Path = SOURCE_ROOT) -> dict[str, Any]:
    source_root = Path(source_root)
    if source_root.is_symlink():
        raise ValueError("UVM source root must not be a symlink")
    source_root = source_root.resolve(strict=True)
    if source_root.name != "nvidia-uvm" or source_root.parent.name != "kernel-open":
        raise ValueError("source root must be an R580 kernel-open/nvidia-uvm tree")
    package = source_root.parent.parent
    if package.name != f"NVIDIA-kernel-module-source-{SOURCE_TAG}":
        raise ValueError("source tree is not NVIDIA R580.178.04")

    archive = SOURCE_ARCHIVE.resolve(strict=True)
    archive_sha256 = _sha256(archive)
    if archive_sha256 != EXPECTED_ARCHIVE_SHA256:
        raise ValueError("pinned R580 source archive SHA-256 mismatch")
    patch = ISOLATION_PATCH.resolve(strict=True)
    build_report = BUILD_REPORT.resolve(strict=True)
    build = json.loads(build_report.read_text(encoding="utf-8"))
    patch_record = next(
        (item for item in build.get("inputs", {}).get("patches", [])
         if item.get("path", "").endswith(ISOLATION_PATCH.name)),
        None,
    )
    pmm_patch_record = next(
        (item for item in build.get("inputs", {}).get("patches", [])
         if item.get("path", "").endswith(PMM_RETRY_PATCH.name)),
        None,
    )
    hmm_patch_record = next(
        (item for item in build.get("inputs", {}).get("patches", [])
         if item.get("path", "").endswith(HMM_ISOLATION_PATCH.name)),
        None,
    )
    expected_source_package = str(package)
    if build.get("build", {}).get("exit_code") != 0:
        raise ValueError("the source's pinned module build did not succeed")
    if build.get("qualification", {}).get("module_loaded_or_installed") is not False:
        raise ValueError("unexpected module installation/load state in the build report")
    if build.get("inputs", {}).get("source_package") != expected_source_package:
        raise ValueError("build report does not identify the audited source package")
    if not patch_record or patch_record.get("sha256") != _sha256(patch):
        raise ValueError("build report does not prove application of the current isolation patch")
    if not pmm_patch_record or pmm_patch_record.get("sha256") != _sha256(PMM_RETRY_PATCH):
        raise ValueError("build report does not prove application of the PMM lock-release patch")
    if not hmm_patch_record or hmm_patch_record.get("sha256") != _sha256(HMM_ISOLATION_PATCH):
        raise ValueError("build report does not prove application of the isolated HMM guard patch")
    source_files = {}
    for name in SOURCE_FILES:
        path = source_root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"source must be a regular non-symlink file: {name}")
        source_files[name] = {
            "path": project_path(path),
            "sha256": _sha256(path),
            "bytes": path.stat().st_size,
        }

    result = analyze_sources(source_root)
    return {
        "schema": "nvidia-r580-uvm-pmm-wait-lock-context-v5",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_release": SOURCE_TAG,
        "qualification": {
            "level": "analyzed-statically",
            "module_loaded_or_installed": False,
            "runtime_or_hardware_validated": False,
        },
        "inputs": {
            "source_archive": {"path": project_path(archive), "sha256": archive_sha256},
            "isolation_patch": {"path": project_path(patch), "sha256": _sha256(patch)},
            "pmm_retry_patch": {
                "path": project_path(PMM_RETRY_PATCH),
                "sha256": _sha256(PMM_RETRY_PATCH),
            },
            "hmm_isolation_patch": {
                "path": project_path(HMM_ISOLATION_PATCH),
                "sha256": _sha256(HMM_ISOLATION_PATCH),
            },
            "build_report": {"path": project_path(build_report), "sha256": _sha256(build_report)},
            "source_files": source_files,
        },
        "result": result,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=SOURCE_ROOT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = audit_sources(args.source_root)
        if args.output:
            write_private_evidence_report(args.output, report)
        print(json.dumps(report, indent=2, sort_keys=True))
    except (OSError, ValueError, RuntimeError) as error:
        print(f"PMM wait audit failed: {error}", file=sys.stderr)
        return 2
    return 1 if report["result"]["status"] == "unresolved" else 0


if __name__ == "__main__":
    raise SystemExit(main())
