/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../src/hybrid580_uvm_info_registry.h"

int main(void)
{
    struct hybrid580_uvm_info_registry registry = {0};
    struct hybrid580_uvm_info_registry channel_registry = {0};
    struct hybrid580_uvm_info_entry fault = {0};
    struct hybrid580_uvm_info_entry access = {0};
    struct hybrid580_uvm_info_entry csl = {0};
    struct hybrid580_uvm_info_entry csl_legacy = {0};
    struct hybrid580_uvm_info_entry channel_csl = {0};
    struct hybrid580_uvm_info_entry *retiring = NULL;
    struct hybrid580_uvm_info_entry *removed = NULL;
    struct hybrid580_uvm_info_pin pin = {0};
    struct hybrid580_uvm_info_pin channel_pin = {0};
    struct hybrid580_uvm_info_pin context_pins[2] = {{0}};
    struct hybrid580_uvm_info_pin dirty_pins[2] = {{0}};
    enum hybrid580_uvm_provider context_provider = 0;
    uintptr_t mixed_contexts[] = {0x3030, 0x4040};
    dirty_pins[0].active = 1;

    assert(hybrid580_uvm_info_registry_record(
               &registry, &fault, 0x1010, 0x1001,
               HYBRID580_UVM_PROVIDER_OPEN, HYBRID580_UVM_INFO_FAULT) ==
           HYBRID580_UVM_INFO_OK);
    assert(hybrid580_uvm_info_registry_record(
               &registry, &access, 0x2020, 0x2001,
               HYBRID580_UVM_PROVIDER_LEGACY,
               HYBRID580_UVM_INFO_ACCESS_COUNTER) == HYBRID580_UVM_INFO_OK);
    assert(hybrid580_uvm_info_registry_record(
               &registry, &csl, 0x3030, 0x1001,
               HYBRID580_UVM_PROVIDER_OPEN,
               HYBRID580_UVM_INFO_CSL) == HYBRID580_UVM_INFO_OK);
    assert(hybrid580_uvm_info_registry_record(
               &registry, &csl_legacy, 0x4040, 0x2001,
               HYBRID580_UVM_PROVIDER_LEGACY,
               HYBRID580_UVM_INFO_CSL) == HYBRID580_UVM_INFO_OK);
    assert(registry.count == 4);
    assert(hybrid580_uvm_info_registry_begin_retire(
               &registry, 0x3030, HYBRID580_UVM_INFO_CSL, 0x1001,
               &retiring) == HYBRID580_UVM_INFO_OK);
    assert(hybrid580_uvm_info_registry_set_channel_parent(
               &registry, 0x3030, 0x1001, 0x3001) == HYBRID580_UVM_INFO_OK);
    assert(hybrid580_uvm_info_registry_set_channel_parent(
               &registry, 0x3030, 0x1001, 0x3002) ==
           HYBRID580_UVM_INFO_OWNER_MISMATCH);
    assert(hybrid580_uvm_info_registry_finish_retire(
               &registry, retiring, 0, &removed) == HYBRID580_UVM_INFO_OK);
    assert(removed == NULL);
    assert(hybrid580_uvm_info_registry_record(
               &registry, &(struct hybrid580_uvm_info_entry){0}, 0x1010,
               0x2001, HYBRID580_UVM_PROVIDER_LEGACY,
               HYBRID580_UVM_INFO_ACCESS_COUNTER) ==
           HYBRID580_UVM_INFO_DUPLICATE);

    assert(hybrid580_uvm_info_registry_pin(
               &registry, 0x1010, HYBRID580_UVM_INFO_FAULT, 0x1001,
               &pin) == HYBRID580_UVM_INFO_OK);
    assert(pin.provider == HYBRID580_UVM_PROVIDER_OPEN &&
           pin.device_identity == 0x1001 && fault.active_calls == 1);
    assert(hybrid580_uvm_info_registry_pin(
               &registry, 0x1010, HYBRID580_UVM_INFO_FAULT, 0x2001,
               &(struct hybrid580_uvm_info_pin){0}) ==
           HYBRID580_UVM_INFO_OWNER_MISMATCH);
    assert(hybrid580_uvm_info_registry_begin_retire(
               &registry, 0x1010, HYBRID580_UVM_INFO_FAULT, 0x1001,
               &retiring) == HYBRID580_UVM_INFO_BUSY);
    assert(retiring == NULL &&
           hybrid580_uvm_info_registry_has_parent(&registry, 0x1001));
    assert(hybrid580_uvm_info_registry_unpin(&registry, &pin) ==
           HYBRID580_UVM_INFO_OK);

    assert(hybrid580_uvm_info_registry_begin_retire(
               &registry, 0x1010, HYBRID580_UVM_INFO_FAULT, 0x1001,
               &retiring) == HYBRID580_UVM_INFO_OK);
    assert(retiring == &fault && fault.retiring);
    assert(hybrid580_uvm_info_registry_pin(
               &registry, 0x1010, HYBRID580_UVM_INFO_FAULT, 0x1001,
               &pin) == HYBRID580_UVM_INFO_BUSY);
    assert(hybrid580_uvm_info_registry_finish_retire(
               &registry, retiring, 0, &removed) == HYBRID580_UVM_INFO_OK);
    assert(!fault.retiring && removed == NULL && registry.count == 4);

    assert(hybrid580_uvm_info_registry_pin(
               &registry, 0x1010, HYBRID580_UVM_INFO_FAULT, 0x1001,
               &pin) == HYBRID580_UVM_INFO_OK);
    assert(hybrid580_uvm_info_registry_unpin(&registry, &pin) ==
           HYBRID580_UVM_INFO_OK);
    assert(hybrid580_uvm_info_registry_begin_retire(
               &registry, 0x1010, HYBRID580_UVM_INFO_FAULT, 0x1001,
               &retiring) == HYBRID580_UVM_INFO_OK);
    assert(hybrid580_uvm_info_registry_finish_retire(
               &registry, retiring, 1, &removed) == HYBRID580_UVM_INFO_OK);
    assert(removed == &fault && registry.count == 3 &&
           hybrid580_uvm_info_registry_has_parent(&registry, 0x1001));

    assert(hybrid580_uvm_info_registry_pin_many_same_provider(
               &registry, mixed_contexts, 2, HYBRID580_UVM_INFO_CSL,
               context_pins, &context_provider) ==
           HYBRID580_UVM_INFO_CROSS_PROVIDER);
    assert(!context_pins[0].active && !context_pins[1].active &&
           csl.active_calls == 0 && csl_legacy.active_calls == 0 &&
           context_provider == 0);
    assert(hybrid580_uvm_info_registry_pin_many_same_provider(
               &registry, mixed_contexts, 2, HYBRID580_UVM_INFO_CSL,
               dirty_pins, &context_provider) == HYBRID580_UVM_INFO_INVALID);
    assert(dirty_pins[0].active && !dirty_pins[1].active &&
           csl.active_calls == 0 && csl_legacy.active_calls == 0);

    assert(hybrid580_uvm_info_registry_pin(
               &registry, 0x3030, HYBRID580_UVM_INFO_CSL, 0x1001,
               &pin) == HYBRID580_UVM_INFO_OK);
    assert(pin.provider == HYBRID580_UVM_PROVIDER_OPEN);
    assert(hybrid580_uvm_info_registry_unpin(&registry, &pin) ==
           HYBRID580_UVM_INFO_OK);
    assert(hybrid580_uvm_info_registry_begin_retire(
               &registry, 0x3030, HYBRID580_UVM_INFO_CSL, 0x1001,
               &retiring) == HYBRID580_UVM_INFO_OK);
    assert(hybrid580_uvm_info_registry_finish_retire(
               &registry, retiring, 1, &removed) == HYBRID580_UVM_INFO_OK);
    assert(removed == &csl && registry.count == 2 &&
           !hybrid580_uvm_info_registry_has_parent(&registry, 0x1001) &&
           hybrid580_uvm_info_registry_quarantine_channel_parent(
               &registry, 0x3001) == 0);

    assert(hybrid580_uvm_info_registry_record(
               &channel_registry, &channel_csl, 0x5050, 0x5001,
               HYBRID580_UVM_PROVIDER_OPEN,
               HYBRID580_UVM_INFO_CSL) == HYBRID580_UVM_INFO_OK);
    assert(hybrid580_uvm_info_registry_begin_retire(
               &channel_registry, 0x5050, HYBRID580_UVM_INFO_CSL, 0x5001,
               &retiring) == HYBRID580_UVM_INFO_OK);
    assert(hybrid580_uvm_info_registry_set_channel_parent(
               &channel_registry, 0x5050, 0x5001, 0x5002) ==
           HYBRID580_UVM_INFO_OK);
    assert(hybrid580_uvm_info_registry_finish_retire(
               &channel_registry, retiring, 0, &removed) ==
           HYBRID580_UVM_INFO_OK);
    assert(hybrid580_uvm_info_registry_quarantine_channel_parent(
               &channel_registry, 0x5002) == 1);
    assert(hybrid580_uvm_info_registry_pin(
               &channel_registry, 0x5050, HYBRID580_UVM_INFO_CSL, 0x5001,
               &channel_pin) == HYBRID580_UVM_INFO_QUARANTINED);
    assert(hybrid580_uvm_info_registry_begin_retire(
               &channel_registry, 0x5050, HYBRID580_UVM_INFO_CSL, 0x5001,
               &retiring) == HYBRID580_UVM_INFO_QUARANTINED);

    assert(hybrid580_uvm_info_registry_pin(
               &registry, 0x2020, HYBRID580_UVM_INFO_FAULT, 0x2001,
               &pin) == HYBRID580_UVM_INFO_OWNER_MISMATCH);
    assert(hybrid580_uvm_info_registry_quarantine(&registry, 0x2020) ==
           HYBRID580_UVM_INFO_OK);
    assert(hybrid580_uvm_info_registry_pin(
               &registry, 0x2020, HYBRID580_UVM_INFO_ACCESS_COUNTER, 0x2001,
               &pin) == HYBRID580_UVM_INFO_QUARANTINED);
    assert(hybrid580_uvm_info_registry_has_parent(&registry, 0x2001));

    assert(hybrid580_uvm_info_registry_pin(
               NULL, 0x2020, HYBRID580_UVM_INFO_ACCESS_COUNTER, 0x2001,
               &pin) == HYBRID580_UVM_INFO_INVALID);
    assert(hybrid580_uvm_info_registry_unpin(&registry, &pin) ==
           HYBRID580_UVM_INFO_INVALID);
    puts("UVM info owner, active-call, retire, retry and quarantine checks passed");
    return 0;
}
