/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_UVM_CALLBACK_BRIDGE_H
#define HYBRID580_UVM_CALLBACK_BRIDGE_H

/*
 * CPU-testable lifetime/rollback core for the UVM->RM callback-table
 * registration boundary. The kernel adapter serializes these calls with a
 * mutex. Backend callback tables remain provider-owned; this registry only
 * records the one UVM-owned table whose registration succeeded on both RMs.
 */
struct hybrid580_uvm_callback_backend {
    void *context;
    int (*register_callbacks)(void *context, void *callbacks);
    void (*deregister_callbacks)(void *context);
};

enum hybrid580_uvm_callback_result_code {
    HYBRID580_UVM_CALLBACK_OK = 0,
    HYBRID580_UVM_CALLBACK_INVALID,
    HYBRID580_UVM_CALLBACK_BUSY,
    HYBRID580_UVM_CALLBACK_OPEN_FAILED,
    HYBRID580_UVM_CALLBACK_LEGACY_FAILED,
};

struct hybrid580_uvm_callback_result {
    enum hybrid580_uvm_callback_result_code code;
    int backend_status;
};

struct hybrid580_uvm_callback_registry {
    int registered;
    void *callback_table;
};

static inline struct hybrid580_uvm_callback_result
hybrid580_uvm_callback_register(
    struct hybrid580_uvm_callback_registry *registry,
    void *open_callback_table,
    void *legacy_callback_table,
    struct hybrid580_uvm_callback_backend open,
    struct hybrid580_uvm_callback_backend legacy)
{
    struct hybrid580_uvm_callback_result result = {
        .code = HYBRID580_UVM_CALLBACK_INVALID,
        .backend_status = 0,
    };
    int status;

    if (registry == 0 || open_callback_table == 0 ||
        legacy_callback_table == 0 ||
        open.register_callbacks == 0 || open.deregister_callbacks == 0 ||
        legacy.register_callbacks == 0 || legacy.deregister_callbacks == 0)
        return result;

    if (registry->registered) {
        result.code = HYBRID580_UVM_CALLBACK_BUSY;
        return result;
    }

    status = open.register_callbacks(open.context, open_callback_table);
    if (status != 0) {
        result.code = HYBRID580_UVM_CALLBACK_OPEN_FAILED;
        result.backend_status = status;
        return result;
    }

    status = legacy.register_callbacks(legacy.context, legacy_callback_table);
    if (status != 0) {
        open.deregister_callbacks(open.context);
        result.code = HYBRID580_UVM_CALLBACK_LEGACY_FAILED;
        result.backend_status = status;
        return result;
    }

    registry->callback_table = open_callback_table;
    registry->registered = 1;
    result.code = HYBRID580_UVM_CALLBACK_OK;
    return result;
}

static inline void
hybrid580_uvm_callback_unregister(
    struct hybrid580_uvm_callback_registry *registry,
    struct hybrid580_uvm_callback_backend open,
    struct hybrid580_uvm_callback_backend legacy)
{
    if (registry == 0 || !registry->registered)
        return;

    /* Reverse registration order. Each backend clears its pointer and drains
     * its own interrupt/callback users before the shared UVM table can die. */
    legacy.deregister_callbacks(legacy.context);
    open.deregister_callbacks(open.context);
    registry->callback_table = 0;
    registry->registered = 0;
}

#endif
