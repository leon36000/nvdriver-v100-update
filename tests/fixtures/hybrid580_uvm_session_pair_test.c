/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "../../src/hybrid580_uvm_session_pair.h"

struct fake_provider {
    uintptr_t next_handle;
    uintptr_t failure_handle;
    int create_status;
    enum hybrid580_uvm_destroy_result destroy_result;
    unsigned create_calls;
    unsigned destroy_calls;
    uintptr_t last_destroyed;
};

static int fake_create(void *context, uintptr_t *handle)
{
    struct fake_provider *provider = context;
    ++provider->create_calls;
    *handle = provider->create_status == 0 ? provider->next_handle :
                                               provider->failure_handle;
    return provider->create_status;
}

static enum hybrid580_uvm_destroy_result fake_destroy(void *context, uintptr_t handle)
{
    struct fake_provider *provider = context;
    ++provider->destroy_calls;
    provider->last_destroyed = handle;
    return provider->destroy_result;
}

static struct hybrid580_uvm_provider_ops make_ops(struct fake_provider *provider)
{
    return (struct hybrid580_uvm_provider_ops){
        .context = provider,
        .create = fake_create,
        .destroy = fake_destroy,
    };
}

int main(void)
{
    struct fake_provider open_provider = {.next_handle = 0x1000};
    struct fake_provider legacy_provider = {.next_handle = 0x2000};
    struct hybrid580_uvm_provider_ops open_ops = make_ops(&open_provider);
    struct hybrid580_uvm_provider_ops legacy_ops = make_ops(&legacy_provider);
    struct hybrid580_uvm_session_pair pair = {0};
    int rc;

    assert(hybrid580_uvm_session_pair_publish_identity(&pair, 0x9000) ==
           HYBRID580_UVM_SESSION_INVALID);

    open_provider.create_status = -11;
    rc = hybrid580_uvm_session_pair_create(&pair, open_ops, legacy_ops);
    assert(rc == HYBRID580_UVM_SESSION_OPEN_CREATE_FAILED);
    assert(pair.live_mask == 0 && pair.public_identity == 0);
    assert(open_provider.create_calls == 1 && legacy_provider.create_calls == 0);

    open_provider.create_status = 0;
    legacy_provider.create_status = -22;
    open_provider.destroy_result = HYBRID580_UVM_DESTROYED;
    rc = hybrid580_uvm_session_pair_create(&pair, open_ops, legacy_ops);
    assert(rc == HYBRID580_UVM_SESSION_LEGACY_CREATE_FAILED);
    assert(pair.live_mask == 0 && pair.public_identity == 0);
    assert(open_provider.destroy_calls == 1 && open_provider.last_destroyed == 0x1000);

    open_provider.destroy_result = HYBRID580_UVM_DESTROY_RETRYABLE;
    rc = hybrid580_uvm_session_pair_create(&pair, open_ops, legacy_ops);
    assert(rc == HYBRID580_UVM_SESSION_ROLLBACK_PENDING);
    assert(pair.live_mask == HYBRID580_UVM_PROVIDER_OPEN);
    assert(pair.public_identity == 0 && pair.native_open == 0x1000);
    assert(hybrid580_uvm_session_pair_create(&pair, open_ops, legacy_ops) ==
           HYBRID580_UVM_SESSION_BUSY);
    open_provider.destroy_result = HYBRID580_UVM_DESTROYED;
    assert(hybrid580_uvm_session_pair_destroy(&pair) ==
           HYBRID580_UVM_SESSION_OK);
    assert(pair.live_mask == 0 && pair.public_identity == 0);

    legacy_provider.create_status = 0;
    assert(hybrid580_uvm_session_pair_create(&pair, open_ops, legacy_ops) ==
           HYBRID580_UVM_SESSION_OK);
    assert(pair.public_identity == 0x1000 && pair.native_legacy == 0x2000);
    assert(hybrid580_uvm_session_pair_publish_identity(&pair, 0x9000) ==
           HYBRID580_UVM_SESSION_OK);
    assert(pair.public_identity == 0x9000 && pair.native_open == 0x1000 &&
           pair.native_legacy == 0x2000);
    assert(hybrid580_uvm_session_pair_publish_identity(&pair, 0) ==
           HYBRID580_UVM_SESSION_INVALID);
    assert(pair.public_identity == 0x9000);
    open_provider.destroy_result = HYBRID580_UVM_DESTROYED;
    legacy_provider.destroy_result = HYBRID580_UVM_DESTROY_RETRYABLE;
    assert(hybrid580_uvm_session_pair_destroy(&pair) ==
           HYBRID580_UVM_SESSION_DESTROY_PENDING);
    assert(pair.live_mask == HYBRID580_UVM_PROVIDER_LEGACY);
    assert(pair.public_identity == 0 && pair.native_open == 0 &&
           pair.native_legacy == 0x2000);
    assert(open_provider.destroy_calls == 4); /* successful provider is not destroyed twice */
    legacy_provider.destroy_result = HYBRID580_UVM_DESTROYED;
    assert(hybrid580_uvm_session_pair_destroy(&pair) ==
           HYBRID580_UVM_SESSION_OK);
    assert(legacy_provider.last_destroyed == 0x2000);
    assert(pair.live_mask == 0 && pair.public_identity == 0);

    open_provider.next_handle = 0;
    assert(hybrid580_uvm_session_pair_create(&pair, open_ops, legacy_ops) ==
           HYBRID580_UVM_SESSION_INVALID_HANDLE);

    /* Partial outputs on failed create are owned and rolled back in reverse order. */
    open_provider.next_handle = 0x3100;
    legacy_provider.failure_handle = 0x2100;
    legacy_provider.create_status = -56;
    legacy_provider.destroy_result = HYBRID580_UVM_DESTROYED;
    assert(hybrid580_uvm_session_pair_create(&pair, open_ops, legacy_ops) ==
           HYBRID580_UVM_SESSION_LEGACY_CREATE_FAILED);
    assert(legacy_provider.last_destroyed == 0x2100);
    assert(open_provider.last_destroyed == 0x3100);

    /* Failed first-provider creation can also leave a retryable partial handle. */
    open_provider.create_status = -57;
    open_provider.failure_handle = 0x1101;
    open_provider.destroy_result = HYBRID580_UVM_DESTROY_RETRYABLE;
    assert(hybrid580_uvm_session_pair_create(&pair, open_ops, legacy_ops) ==
           HYBRID580_UVM_SESSION_ROLLBACK_PENDING);
    assert(pair.native_open == 0x1101 &&
           pair.live_mask == HYBRID580_UVM_PROVIDER_OPEN);
    open_provider.create_status = 0;
    open_provider.failure_handle = 0;
    open_provider.destroy_result = HYBRID580_UVM_DESTROYED;
    assert(hybrid580_uvm_session_pair_destroy(&pair) ==
           HYBRID580_UVM_SESSION_OK);

    /* An ambiguous provider result is never retried, even on explicit cleanup. */
    open_provider.next_handle = 0x3000;
    open_provider.destroy_result = HYBRID580_UVM_DESTROY_AMBIGUOUS;
    legacy_provider.create_status = -55;
    assert(hybrid580_uvm_session_pair_create(&pair, open_ops, legacy_ops) ==
           HYBRID580_UVM_SESSION_QUARANTINED);
    assert(pair.state == HYBRID580_UVM_SESSION_PAIR_QUARANTINED);
    unsigned ambiguous_calls = open_provider.destroy_calls;
    assert(hybrid580_uvm_session_pair_destroy(&pair) ==
           HYBRID580_UVM_SESSION_QUARANTINED);
    assert(open_provider.destroy_calls == ambiguous_calls);
    assert(pair.public_identity == 0 && pair.native_open == 0x3000);
    puts("hybrid580 UVM session pair passed");
    return 0;
}
