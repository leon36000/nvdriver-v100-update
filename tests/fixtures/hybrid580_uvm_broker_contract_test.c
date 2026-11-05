/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "../../src/hybrid580_uvm_owner_map.h"
#include "../../src/hybrid580_uvm_session_pair.h"

struct fake_provider {
    uintptr_t handle;
    int create_status;
    enum hybrid580_uvm_destroy_result destroy_result;
    unsigned destroys;
};

static int create(void *context, uintptr_t *handle)
{
    struct fake_provider *provider = context;
    *handle = provider->create_status == 0 ? provider->handle : 0;
    return provider->create_status;
}

static enum hybrid580_uvm_destroy_result destroy(void *context, uintptr_t handle)
{
    struct fake_provider *provider = context;
    assert(handle == provider->handle);
    ++provider->destroys;
    return provider->destroy_result;
}

int main(void)
{
    struct fake_provider open_backend = {
        .handle = 0x1000,
        .destroy_result = HYBRID580_UVM_DESTROYED,
    };
    struct fake_provider legacy_backend = {
        .handle = 0x2000,
        .destroy_result = HYBRID580_UVM_DESTROYED,
    };
    struct hybrid580_uvm_provider_ops open_ops = {
        .context = &open_backend,
        .create = create,
        .destroy = destroy,
    };
    struct hybrid580_uvm_provider_ops legacy_ops = {
        .context = &legacy_backend,
        .create = create,
        .destroy = destroy,
    };
    struct hybrid580_uvm_owner_entry entries[4];
    struct hybrid580_uvm_owner_map map;
    struct hybrid580_uvm_session_pair pair = {0};
    struct hybrid580_uvm_owner_ref open_ref = {0};
    struct hybrid580_uvm_owner_ref legacy_ref = {0};

    assert(hybrid580_uvm_owner_map_init(&map, entries, 4) == HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_session_pair_create(&pair, open_ops, legacy_ops) ==
           HYBRID580_UVM_SESSION_OK);
    assert(pair.public_identity == 0x1000);
    assert(hybrid580_uvm_owner_add(&map, pair.public_identity, HYBRID580_UVM_SESSION, 0,
                                   HYBRID580_UVM_PROVIDER_BOTH,
                                   pair.native_open, pair.native_legacy) ==
           HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_pin(&map, pair.public_identity, HYBRID580_UVM_SESSION,
                                   HYBRID580_UVM_PROVIDER_OPEN, &open_ref) ==
           HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_pin(&map, pair.public_identity, HYBRID580_UVM_SESSION,
                                   HYBRID580_UVM_PROVIDER_LEGACY, &legacy_ref) ==
           HYBRID580_UVM_OWNER_OK);
    assert(open_ref.native_handle == 0x1000 && legacy_ref.native_handle == 0x2000);
    assert(hybrid580_uvm_owner_unpin(&map, &legacy_ref) == HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_owner_unpin(&map, &open_ref) == HYBRID580_UVM_OWNER_OK);

    assert(hybrid580_uvm_owner_begin_retire(&map, pair.public_identity,
                                             HYBRID580_UVM_SESSION) ==
           HYBRID580_UVM_OWNER_OK);
    assert(hybrid580_uvm_session_pair_destroy(&pair) == HYBRID580_UVM_SESSION_OK);
    assert(hybrid580_uvm_owner_finish_retire(&map, 0x1000, HYBRID580_UVM_SESSION) ==
           HYBRID580_UVM_OWNER_OK);
    assert(map.count == 0 && open_backend.destroys == 1 && legacy_backend.destroys == 1);

    /* A map insertion failure must keep the pre-existing owner intact and
     * explicitly roll back both newly created provider sessions. */
    assert(hybrid580_uvm_owner_add(&map, 0x1000, HYBRID580_UVM_SESSION, 0,
                                   HYBRID580_UVM_PROVIDER_OPEN, 0x1000, 0) ==
           HYBRID580_UVM_OWNER_OK);
    open_backend.destroys = 0;
    legacy_backend.destroys = 0;
    assert(hybrid580_uvm_session_pair_create(&pair, open_ops, legacy_ops) ==
           HYBRID580_UVM_SESSION_OK);
    assert(hybrid580_uvm_owner_add(&map, pair.public_identity, HYBRID580_UVM_SESSION, 0,
                                   HYBRID580_UVM_PROVIDER_BOTH,
                                   pair.native_open, pair.native_legacy) ==
           HYBRID580_UVM_OWNER_DUPLICATE);
    assert(hybrid580_uvm_session_pair_destroy(&pair) == HYBRID580_UVM_SESSION_OK);
    assert(open_backend.destroys == 1 && legacy_backend.destroys == 1);
    size_t existing = hybrid580_uvm_owner_find(&map, 0x1000);
    assert(existing != SIZE_MAX && map.entries[existing].provider_mask ==
           HYBRID580_UVM_PROVIDER_OPEN);

    puts("hybrid580 UVM session/owner composition passed");
    return 0;
}
