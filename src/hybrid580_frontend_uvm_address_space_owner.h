/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_FRONTEND_UVM_ADDRESS_SPACE_OWNER_H
#define HYBRID580_FRONTEND_UVM_ADDRESS_SPACE_OWNER_H

struct hybrid_front_uvm_address_space_owner_pin;
struct file;

struct hybrid580_frontend_address_space_owner {
    unsigned int backend; /* HYBRID580_BACKEND_LEGACY or _OPEN */
    NvHandle backend_root;
    NvHandle backend_vaspace;
    struct hybrid_front_uvm_address_space_owner_pin *pin;
};

/* Resolve and pin the public FERMI_VASPACE_A under the exact frontend file
 * resolved by UVM at ioctl entry. The pin spans RM DupAddressSpace so FREE
 * and final control-file release cannot race the native duplicate operation.
 */
NvU32 hybrid580_frontend_uvm_address_space_owner_pin_v1(
    struct file *rm_control_file, NvHandle public_client, NvHandle public_vaspace,
    struct hybrid580_frontend_address_space_owner *owner);
void hybrid580_frontend_uvm_address_space_owner_unpin_v1(
    struct hybrid580_frontend_address_space_owner *owner);
void hybrid580_frontend_uvm_address_space_owner_quarantine_v1(
    struct hybrid580_frontend_address_space_owner *owner);

#endif
