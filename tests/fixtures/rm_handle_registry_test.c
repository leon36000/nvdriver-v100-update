/* SPDX-License-Identifier: MIT */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../../src/rm_handle_registry.h"

#define CHECK(value) do { \
    if (!(value)) { \
        fprintf(stderr, "registry check failed at line %d: %s\n", __LINE__, #value); \
        return 1; \
    } \
} while (0)

int main(void)
{
    struct rm_handle_registry registry;
    uint32_t class_id = 0;
    memset(&registry, 0, sizeof(registry));

    CHECK(rm_handle_registry_lookup(&registry, 10, 0, &class_id) == RM_HANDLE_ABSENT);
    CHECK(rm_handle_registry_lookup(&registry, 0, 20, &class_id) == RM_HANDLE_INVALID_ROOT);
    CHECK(rm_handle_registry_lookup(&registry, 10, 20, &class_id) == RM_HANDLE_NOT_OBSERVED);
    CHECK(rm_handle_registry_insert(&registry, 10, 20, 0, 0x80) == 0);
    CHECK(registry.count == 1);
    CHECK(rm_handle_registry_lookup(&registry, 10, 20, &class_id) == RM_HANDLE_RESOLVED);
    CHECK(class_id == 0x80);
    CHECK(rm_handle_registry_insert(&registry, 10, 20, 0, 0x9067) == -2);
    CHECK(rm_handle_registry_insert(&registry, 11, 20, 0, 0x9067) == 0);
    CHECK(rm_handle_registry_lookup(&registry, 11, 20, &class_id) == RM_HANDLE_RESOLVED);
    CHECK(class_id == 0x9067);
    CHECK(rm_handle_registry_remove(&registry, 10, 20) == 1);
    CHECK(rm_handle_registry_lookup(&registry, 10, 20, &class_id) == RM_HANDLE_NOT_OBSERVED);
    CHECK(rm_handle_registry_lookup(&registry, 11, 20, &class_id) == RM_HANDLE_RESOLVED);

    /* A freed numeric handle may be reused by the RM for another class. */
    CHECK(rm_handle_registry_insert(&registry, 10, 20, 0, 0x3e) == 0);
    CHECK(rm_handle_registry_lookup(&registry, 10, 20, &class_id) == RM_HANDLE_RESOLVED);
    CHECK(class_id == 0x3e);

    /* Corrupt/duplicated evidence is reported as ambiguous rather than guessed. */
    registry.entries[2] = registry.entries[0];
    registry.entries[2].active = 1;
    ++registry.count;
    CHECK(rm_handle_registry_lookup(&registry, 10, 20, &class_id) == RM_HANDLE_AMBIGUOUS);
    CHECK(rm_handle_registry_remove(&registry, 10, 20) == -2);
    CHECK(rm_handle_registry_remove_root(&registry, 10) == 2);
    CHECK(rm_handle_registry_lookup(&registry, 10, 20, &class_id) == RM_HANDLE_NOT_OBSERVED);
    CHECK(registry.count == 1);

    /* Parent class is resolved through live root-scoped handles, with no raw
     * handle exposed by the lookup contract. */
    memset(&registry, 0, sizeof(registry));
    CHECK(rm_handle_registry_insert(&registry, 10, 100, 0, 0x41) == 0);
    CHECK(rm_handle_registry_insert(&registry, 10, 200, 100, 0x80) == 0);
    CHECK(rm_handle_registry_insert(&registry, 10, 300, 200, 0xcec0) == 0);
    uint32_t root = 0;
    CHECK(rm_handle_registry_root_for_handle(&registry, 100, &root) ==
          RM_HANDLE_RESOLVED);
    CHECK(root == 10);
    CHECK(rm_handle_registry_root_for_handle(&registry, 300, &root) ==
          RM_HANDLE_RESOLVED);
    CHECK(root == 10);
    CHECK(rm_handle_registry_root_for_handle(&registry, 999, &root) ==
          RM_HANDLE_NOT_OBSERVED);
    CHECK(root == 0);
    CHECK(rm_handle_registry_lookup_parent_class(&registry, 10, 300,
                                                  &class_id) == RM_HANDLE_RESOLVED);
    CHECK(class_id == 0x80);
    CHECK(rm_handle_registry_remove(&registry, 10, 200) == 1);
    CHECK(rm_handle_registry_lookup_parent_class(&registry, 10, 300,
                                                  &class_id) == RM_HANDLE_NOT_OBSERVED);
    CHECK(class_id == 0);

    /* Missing observed target and duplicated identity are never guessed. */
    CHECK(rm_handle_registry_lookup_parent_class(&registry, 10, 999,
                                                  &class_id) == RM_HANDLE_NOT_OBSERVED);
    registry.entries[3] = registry.entries[1];
    registry.entries[3].active = 1;
    ++registry.count;
    registry.entries[4] = registry.entries[3];
    registry.entries[4].active = 1;
    ++registry.count;
    CHECK(rm_handle_registry_lookup_parent_class(&registry, 10, 300,
                                                  &class_id) == RM_HANDLE_AMBIGUOUS);

    /* A client handle reused in another root cannot choose a control target. */
    CHECK(rm_handle_registry_insert(&registry, 11, 100, 0, 0x41) == 0);
    CHECK(rm_handle_registry_root_for_handle(&registry, 100, &root) ==
          RM_HANDLE_AMBIGUOUS);
    CHECK(root == 0);

    puts("RM handle registry unit checks passed");
    return 0;
}
