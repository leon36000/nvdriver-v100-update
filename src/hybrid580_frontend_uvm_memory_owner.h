/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_FRONTEND_UVM_MEMORY_OWNER_H
#define HYBRID580_FRONTEND_UVM_MEMORY_OWNER_H

struct hybrid580_frontend_memory_owner_pin;

struct hybrid580_frontend_memory_owner {
    unsigned int backend; /* HYBRID580_BACKEND_LEGACY or _OPEN */
    NvHandle backend_root;
    NvHandle backend_memory;
    struct hybrid580_frontend_memory_owner_pin *pin;
};

/* Pin the tracked source allocation while UVM asks its owner RM to duplicate
 * it. Cross-provider requests are rejected by the UVM bridge before dispatch. */
NvU32 hybrid580_frontend_uvm_memory_owner_pin_v1(
    int rm_control_fd, NvHandle public_client, NvHandle public_memory,
    struct hybrid580_frontend_memory_owner *owner);
void hybrid580_frontend_uvm_memory_owner_unpin_v1(
    struct hybrid580_frontend_memory_owner *owner);
void hybrid580_frontend_uvm_memory_owner_quarantine_v1(
    struct hybrid580_frontend_memory_owner *owner);

#endif
