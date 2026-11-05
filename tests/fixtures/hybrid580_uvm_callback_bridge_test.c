/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../../src/hybrid580_uvm_callback_bridge.h"

struct event_log {
    char events[32];
    unsigned used;
};

struct fake_backend {
    const char *name;
    int register_status;
    unsigned register_calls;
    unsigned deregister_calls;
    void *last_callbacks;
    struct event_log *log;
};

static int fake_register(void *context, void *callbacks)
{
    struct fake_backend *backend = context;
    assert(callbacks != NULL);
    ++backend->register_calls;
    backend->last_callbacks = callbacks;
    backend->log->events[backend->log->used++] = backend->name[0];
    return backend->register_status;
}

static void fake_deregister(void *context)
{
    struct fake_backend *backend = context;
    ++backend->deregister_calls;
    backend->log->events[backend->log->used++] = (char)(backend->name[0] + 32);
}

static struct hybrid580_uvm_callback_backend make_backend(struct fake_backend *fake)
{
    return (struct hybrid580_uvm_callback_backend) {
        .context = fake,
        .register_callbacks = fake_register,
        .deregister_callbacks = fake_deregister,
    };
}

int main(void)
{
    struct event_log log = {0};
    int open_callback_table;
    int legacy_callback_table;
    int candidate_open_callback_table;
    int candidate_legacy_callback_table;
    struct fake_backend open = {.name = "Open", .log = &log};
    struct fake_backend legacy = {.name = "Legacy", .log = &log};
    struct hybrid580_uvm_callback_backend open_backend = make_backend(&open);
    struct hybrid580_uvm_callback_backend legacy_backend = make_backend(&legacy);
    struct hybrid580_uvm_callback_registry registry = {0};
    struct hybrid580_uvm_callback_result result;

    result = hybrid580_uvm_callback_register(&registry, NULL,
                                               &legacy_callback_table,
                                               open_backend, legacy_backend);
    assert(result.code == HYBRID580_UVM_CALLBACK_INVALID);
    assert(open.register_calls == 0 && legacy.register_calls == 0);

    open.register_status = -11;
    result = hybrid580_uvm_callback_register(&registry, &open_callback_table,
                                               &legacy_callback_table,
                                               open_backend, legacy_backend);
    assert(result.code == HYBRID580_UVM_CALLBACK_OPEN_FAILED);
    assert(result.backend_status == -11);
    assert(open.register_calls == 1 && legacy.register_calls == 0);
    assert(open.deregister_calls == 0 && registry.registered == 0);

    open.register_status = 0;
    legacy.register_status = -22;
    result = hybrid580_uvm_callback_register(&registry, &open_callback_table,
                                               &legacy_callback_table,
                                               open_backend, legacy_backend);
    assert(result.code == HYBRID580_UVM_CALLBACK_LEGACY_FAILED);
    assert(result.backend_status == -22);
    assert(open.register_calls == 2 && legacy.register_calls == 1);
    assert(open.deregister_calls == 1 && legacy.deregister_calls == 0);
    assert(open.last_callbacks == &open_callback_table);
    assert(legacy.last_callbacks == &legacy_callback_table);
    assert(registry.registered == 0 && registry.callback_table == NULL);

    legacy.register_status = 0;
    result = hybrid580_uvm_callback_register(&registry, &open_callback_table,
                                               &legacy_callback_table,
                                               open_backend, legacy_backend);
    assert(result.code == HYBRID580_UVM_CALLBACK_OK);
    assert(registry.registered == 1 &&
           registry.callback_table == &open_callback_table);
    assert(open.register_calls == 3 && legacy.register_calls == 2);

    result = hybrid580_uvm_callback_register(&registry,
                                               &candidate_open_callback_table,
                                               &candidate_legacy_callback_table,
                                               open_backend, legacy_backend);
    assert(result.code == HYBRID580_UVM_CALLBACK_BUSY);
    assert(open.register_calls == 3 && legacy.register_calls == 2);
    assert(registry.callback_table == &open_callback_table);
    assert(open.last_callbacks == &open_callback_table);
    assert(legacy.last_callbacks == &legacy_callback_table);

    hybrid580_uvm_callback_unregister(&registry, open_backend, legacy_backend);
    assert(open.deregister_calls == 2 && legacy.deregister_calls == 1);
    assert(registry.registered == 0 && registry.callback_table == NULL);
    assert(strcmp(log.events, "OOLoOLlo") == 0);

    hybrid580_uvm_callback_unregister(&registry, open_backend, legacy_backend);
    assert(open.deregister_calls == 2 && legacy.deregister_calls == 1);
    puts("UVM callback registration fanout/rollback/reverse-unregister scenarios passed");
    return 0;
}
