/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../src/hybrid580_uvm_owner_map.h"

int main(void)
{
    struct hybrid580_uvm_owner_entry entries[8];
    struct hybrid580_uvm_owner_map map;
    struct hybrid580_uvm_owner_ref session_ref = {0};
    struct hybrid580_uvm_owner_ref device_ref = {0};
    struct hybrid580_uvm_owner_ref second_ref = {0};
    struct hybrid580_uvm_owner_ref pair_first = {0};
    struct hybrid580_uvm_owner_ref pair_second = {0};
    struct hybrid580_uvm_owner_ref cleanup_ref = {0};
    struct hybrid580_uvm_owner_ref stale_ref = {0};
    struct hybrid580_uvm_owner_ref forged_ref = {0};
    int rc;

    assert(hybrid580_uvm_owner_map_init(&map, entries, 8) == HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_add(&map, 0x2000, HYBRID580_UVM_SESSION, 0,
                                   HYBRID580_UVM_PROVIDER_BOTH, 0x2000, 0x3000) ==
           HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_add(&map, 0x4000, HYBRID580_UVM_DEVICE, 0x2000,
                                   HYBRID580_UVM_PROVIDER_OPEN, 0x4000, 0) ==
           HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_add(&map, 0x5000, HYBRID580_UVM_DEVICE, 0x2000,
                                   HYBRID580_UVM_PROVIDER_LEGACY, 0, 0x5000) ==
           HYBRID580_UVM_OWNER_OK);

    assert(hybrid580_uvm_owner_pin(&map, 0x2000, HYBRID580_UVM_SESSION,
                                   HYBRID580_UVM_PROVIDER_LEGACY, &session_ref) ==
           HYBRID580_UVM_OWNER_OK);
    assert(session_ref.native_handle == 0x3000);
    assert(hybrid580_uvm_owner_pin(&map, 0x4000, HYBRID580_UVM_DEVICE,
                                   HYBRID580_UVM_PROVIDER_OPEN, &device_ref) ==
           HYBRID580_UVM_OWNER_OK);
    assert(device_ref.native_handle == 0x4000);
    assert(hybrid580_uvm_owner_pin(&map, 0x5000, HYBRID580_UVM_DEVICE,
                                   HYBRID580_UVM_PROVIDER_OPEN, &second_ref) ==
           HYBRID580_UVM_OWNER_WRONG_PROVIDER);
    assert(hybrid580_uvm_owner_pin_pair(&map, 0x4000, HYBRID580_UVM_DEVICE,
                                        0x5000, HYBRID580_UVM_DEVICE,
                                        HYBRID580_UVM_PROVIDER_OPEN,
                                        &pair_first, &pair_second) ==
           HYBRID580_UVM_OWNER_WRONG_PROVIDER);
    assert(hybrid580_uvm_owner_unpin(&map, &device_ref) == HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_unpin(&map, &session_ref) == HYBRID580_UVM_OWNER_OK);

    assert(hybrid580_uvm_owner_pin_pair(&map, 0x4000, HYBRID580_UVM_DEVICE,
                                        0x4000, HYBRID580_UVM_DEVICE,
                                        HYBRID580_UVM_PROVIDER_OPEN,
                                        &pair_first, &pair_second) ==
           HYBRID580_UVM_OWNER_OK);
    assert(pair_first.native_handle == 0x4000 && pair_second.native_handle == 0x4000);
    assert(hybrid580_uvm_owner_unpin(&map, &pair_second) == HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_unpin(&map, &pair_first) == HYBRID580_UVM_OWNER_OK);

    assert(hybrid580_uvm_owner_pin(&map, 0x4000, HYBRID580_UVM_ADDRESS_SPACE,
                                   HYBRID580_UVM_PROVIDER_OPEN, &device_ref) ==
           HYBRID580_UVM_OWNER_WRONG_KIND);
    assert(hybrid580_uvm_owner_begin_retire(&map, 0x2000, HYBRID580_UVM_SESSION) ==
           HYBRID580_UVM_OWNER_HAS_CHILDREN);
    assert(hybrid580_uvm_owner_pin(&map, 0x2000, HYBRID580_UVM_SESSION,
                                   HYBRID580_UVM_PROVIDER_LEGACY, &session_ref) ==
           HYBRID580_UVM_OWNER_BUSY);
    assert(hybrid580_uvm_owner_pin_for_cleanup(&map, 0x2000, HYBRID580_UVM_SESSION,
                                               HYBRID580_UVM_PROVIDER_LEGACY,
                                               &session_ref) == HYBRID580_UVM_OWNER_BUSY);
    assert(hybrid580_uvm_owner_pin(&map, 0x4000, HYBRID580_UVM_DEVICE,
                                   HYBRID580_UVM_PROVIDER_OPEN, &device_ref) ==
           HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_begin_retire(&map, 0x4000, HYBRID580_UVM_DEVICE) ==
           HYBRID580_UVM_OWNER_BUSY);
    assert(hybrid580_uvm_owner_add(&map, 0x6000, HYBRID580_UVM_ADDRESS_SPACE, 0x4000,
                                   HYBRID580_UVM_PROVIDER_OPEN, 0x6000, 0) ==
           HYBRID580_UVM_OWNER_PARENT_CLOSING); /* retiring parent rejects new children */
    assert(device_ref.native_handle == 0x4000); /* the pre-existing pin remains usable */
    assert(hybrid580_uvm_owner_unpin(&map, &device_ref) == HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_begin_retire(&map, 0x4000, HYBRID580_UVM_DEVICE) ==
           HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_pin(&map, 0x4000, HYBRID580_UVM_DEVICE,
                                   HYBRID580_UVM_PROVIDER_OPEN, &device_ref) ==
           HYBRID580_UVM_OWNER_BUSY);
    assert(hybrid580_uvm_owner_pin_for_cleanup(&map, 0x4000, HYBRID580_UVM_DEVICE,
                                               HYBRID580_UVM_PROVIDER_OPEN,
                                               &cleanup_ref) == HYBRID580_UVM_OWNER_OK);
    assert(cleanup_ref.native_handle == 0x4000);
    assert(hybrid580_uvm_owner_pin_for_cleanup(&map, 0x4000, HYBRID580_UVM_DEVICE,
                                               HYBRID580_UVM_PROVIDER_OPEN,
                                               &device_ref) == HYBRID580_UVM_OWNER_BUSY);
    assert(hybrid580_uvm_owner_unpin(&map, &cleanup_ref) == HYBRID580_UVM_OWNER_OK);
    /* A failed provider destruction leaves the closed identity retryable. */
    assert(hybrid580_uvm_owner_pin_for_cleanup(&map, 0x4000, HYBRID580_UVM_DEVICE,
                                               HYBRID580_UVM_PROVIDER_OPEN,
                                               &cleanup_ref) == HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_unpin(&map, &cleanup_ref) == HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_finish_retire(&map, 0x4000, HYBRID580_UVM_DEVICE) ==
           HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_begin_retire(&map, 0x5000, HYBRID580_UVM_DEVICE) ==
           HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_finish_retire(&map, 0x5000, HYBRID580_UVM_DEVICE) ==
           HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_begin_retire(&map, 0x2000, HYBRID580_UVM_SESSION) ==
           HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_finish_retire(&map, 0x2000, HYBRID580_UVM_SESSION) ==
           HYBRID580_UVM_OWNER_OK);
    assert(map.count == 0);

    rc = hybrid580_uvm_owner_add(&map, 0x7000, HYBRID580_UVM_SESSION, 0,
                                 HYBRID580_UVM_PROVIDER_OPEN, 0x7000, 1);
    assert(rc == HYBRID580_UVM_OWNER_INVALID);
    assert(hybrid580_uvm_owner_add(&map, 0x7000, HYBRID580_UVM_SESSION, 0,
                                   HYBRID580_UVM_PROVIDER_OPEN, 0x7000, 0) ==
           HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_add(&map, 0x7000, HYBRID580_UVM_SESSION, 0,
                                   HYBRID580_UVM_PROVIDER_OPEN, 0x7000, 0) ==
           HYBRID580_UVM_OWNER_DUPLICATE);

    assert(hybrid580_uvm_owner_pin(&map, 0x7000, HYBRID580_UVM_SESSION,
                                   HYBRID580_UVM_PROVIDER_OPEN, &session_ref) ==
           HYBRID580_UVM_OWNER_OK);
    forged_ref = session_ref;
    ++forged_ref.native_handle;
    assert(hybrid580_uvm_owner_unpin(&map, &forged_ref) ==
           HYBRID580_UVM_OWNER_BAD_REFERENCE);
    stale_ref = session_ref;
    assert(hybrid580_uvm_owner_unpin(&map, &session_ref) == HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_begin_retire(&map, 0x7000, HYBRID580_UVM_SESSION) ==
           HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_finish_retire(&map, 0x7000, HYBRID580_UVM_SESSION) ==
           HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_add(&map, 0x7000, HYBRID580_UVM_SESSION, 0,
                                   HYBRID580_UVM_PROVIDER_OPEN, 0x7000, 0) ==
           HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_pin(&map, 0x7000, HYBRID580_UVM_SESSION,
                                   HYBRID580_UVM_PROVIDER_OPEN, &session_ref) ==
           HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_unpin(&map, &stale_ref) ==
           HYBRID580_UVM_OWNER_BAD_REFERENCE);
    size_t live_slot = hybrid580_uvm_owner_find(&map, 0x7000);
    assert(live_slot != SIZE_MAX && map.entries[live_slot].active_calls == 1);
    assert(hybrid580_uvm_owner_unpin(&map, &session_ref) == HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_begin_retire(&map, 0x7000, HYBRID580_UVM_SESSION) ==
           HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_finish_retire(&map, 0x7000, HYBRID580_UVM_SESSION) ==
           HYBRID580_UVM_OWNER_OK);
    puts("hybrid580 UVM owner map passed");
    return 0;
}
