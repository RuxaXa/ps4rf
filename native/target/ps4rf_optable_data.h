/* GENERATED FILE -- do not edit.  native/target/gen_optable.py
 *
 * sources   : core/rpc/registry.py (frozen core) + tools/primitive_iface/schema.py (W3)
 *              + tools/dispatch/matrix.py (W7 provider router)
 * generator : native/target/gen_optable.py sha256 4842db4f515c821b77fa2b5ed12d07149e165065578e9ef82c88a72da891f472
 * operations: 38  target wired: 19  target deferred: 19
 * routes    : stub=17 mock_only=4 deferred_privilege=13 deferred_host_chain=1
 * table_sha256: 850bbb1d745414bbcaa6ea85775445674dd28e914ed2971e64bc47b6442f1c4a
 */
#ifndef PS4RF_OPTABLE_DATA_H
#define PS4RF_OPTABLE_DATA_H

#include "jcs.h"

#define PS4RF_OP_TABLE_COUNT 38u
#define PS4RF_OP_WIRED_COUNT 19u
#define PS4RF_OP_DEFERRED_COUNT 19u
#define PS4RF_OP_TABLE_SHA256 "850bbb1d745414bbcaa6ea85775445674dd28e914ed2971e64bc47b6442f1c4a"
#define PS4RF_OP_ROUTE_COUNTS "stub=17 mock_only=4 deferred_privilege=13 deferred_host_chain=1"
#define PS4RF_ARG_ROW_COUNT 56u

enum {
    PS4RF_ROUTE_STUB = 0,
    PS4RF_ROUTE_MOCK_ONLY = 1,
    PS4RF_ROUTE_DEFERRED_PRIVILEGE = 2,
    PS4RF_ROUTE_DEFERRED_HOST_CHAIN = 3,
    /* W14: wired privileged provider -- entered only after the full router validation */
    PS4RF_ROUTE_PRIVILEGED_PROVIDER = 4
};
enum { PS4RF_TARGET_WIRED = 0, PS4RF_TARGET_DEFERRED = 1 };
enum {
    PS4RF_T_INT = 1, PS4RF_T_STR = 2, PS4RF_T_BOOL = 3, PS4RF_T_REF = 4,
    PS4RF_T_HEX32 = 5, PS4RF_T_ARRAY = 6, PS4RF_T_OBJECT = 7
};

/* Fixed-size character arrays instead of pointers on purpose: a table of string
 * pointers would emit ELF relocations, and the loader applies none. The frozen
 * tables therefore live in .rodata as plain bytes. */
typedef struct {
    char name[48];
    char family[16];
    char capability[24];
    char defer_reason[96];
    unsigned char route;
    unsigned char target;
    unsigned char mutating;
    unsigned char recovery_safe;
} ps4rf_op_row;

typedef struct { char name[24]; unsigned char type; unsigned char required; } ps4rf_arg_row;

static const ps4rf_op_row PS4RF_OP_TABLE[PS4RF_OP_TABLE_COUNT] = {
    {"ccp.submit", "ccp", "ccp.submit", "provider state DEFERRED; W8 wires no privileged provider", PS4RF_ROUTE_DEFERRED_PRIVILEGE, PS4RF_TARGET_DEFERRED, 1, 0},
    {"experiment.load", "experiment", "", "wired on the host router; not part of the approved W8 live scope on the target", PS4RF_ROUTE_STUB, PS4RF_TARGET_DEFERRED, 1, 0},
    {"gpuvm.lookup", "gpuvm", "gpuvm.lookup", "provider state DEFERRED; W8 wires no privileged provider", PS4RF_ROUTE_DEFERRED_PRIVILEGE, PS4RF_TARGET_DEFERRED, 1, 0},
    {"gpuvm.map", "gpuvm", "gpuvm.map", "provider state DEFERRED; W8 wires no privileged provider", PS4RF_ROUTE_DEFERRED_PRIVILEGE, PS4RF_TARGET_DEFERRED, 1, 0},
    {"gpuvm.unmap", "gpuvm", "gpuvm.unmap", "provider state DEFERRED; W8 wires no privileged provider", PS4RF_ROUTE_DEFERRED_PRIVILEGE, PS4RF_TARGET_DEFERRED, 1, 0},
    {"ioctl.invoke", "ioctl", "ioctl.invoke", "", PS4RF_ROUTE_PRIVILEGED_PROVIDER, PS4RF_TARGET_WIRED, 1, 0},
    {"kernel.dump.full", "kernel", "kernel.dump.full", "provider state DEFERRED; W8 wires no privileged provider", PS4RF_ROUTE_DEFERRED_PRIVILEGE, PS4RF_TARGET_DEFERRED, 1, 0},
    {"kernel.read", "kernel", "kernel.read", "", PS4RF_ROUTE_PRIVILEGED_PROVIDER, PS4RF_TARGET_WIRED, 1, 0},
    {"kernel.snapshot", "kernel", "kernel.read", "provider state DEFERRED; W8 wires no privileged provider", PS4RF_ROUTE_DEFERRED_PRIVILEGE, PS4RF_TARGET_DEFERRED, 1, 0},
    {"kernel.snapshot.recipe", "kernel", "kernel.read", "", PS4RF_ROUTE_PRIVILEGED_PROVIDER, PS4RF_TARGET_WIRED, 1, 0},
    {"keymgr.claim", "keymgr", "keymgr.claim", "provider state DEFERRED; W8 wires no privileged provider", PS4RF_ROUTE_DEFERRED_PRIVILEGE, PS4RF_TARGET_DEFERRED, 1, 0},
    {"keymgr.release", "keymgr", "keymgr.release", "provider state DEFERRED; W8 wires no privileged provider", PS4RF_ROUTE_DEFERRED_PRIVILEGE, PS4RF_TARGET_DEFERRED, 1, 0},
    {"keymgr.snapshot", "keymgr", "keymgr.snapshot", "provider state DEFERRED; W8 wires no privileged provider", PS4RF_ROUTE_DEFERRED_PRIVILEGE, PS4RF_TARGET_DEFERRED, 1, 0},
    {"memory.alloc", "memory", "memory.alloc", "", PS4RF_ROUTE_STUB, PS4RF_TARGET_WIRED, 1, 0},
    {"memory.free", "memory", "memory.free", "", PS4RF_ROUTE_STUB, PS4RF_TARGET_WIRED, 1, 0},
    {"mock.block", "mock", "", "mock-only fault injection; not part of the native provider surface", PS4RF_ROUTE_MOCK_ONLY, PS4RF_TARGET_DEFERRED, 1, 0},
    {"mock.free_fail", "mock", "", "mock-only fault injection; not part of the native provider surface", PS4RF_ROUTE_MOCK_ONLY, PS4RF_TARGET_DEFERRED, 1, 0},
    {"mock.hang", "mock", "", "mock-only fault injection; not part of the native provider surface", PS4RF_ROUTE_MOCK_ONLY, PS4RF_TARGET_DEFERRED, 1, 0},
    {"mock.leak", "mock", "", "mock-only fault injection; not part of the native provider surface", PS4RF_ROUTE_MOCK_ONLY, PS4RF_TARGET_DEFERRED, 1, 0},
    {"session.ping", "session", "", "", PS4RF_ROUTE_STUB, PS4RF_TARGET_WIRED, 0, 1},
    {"session.shutdown", "session", "", "", PS4RF_ROUTE_STUB, PS4RF_TARGET_WIRED, 0, 1},
    {"session.status", "session", "", "", PS4RF_ROUTE_STUB, PS4RF_TARGET_WIRED, 0, 1},
    {"sync.barrier.create", "sync", "", "", PS4RF_ROUTE_STUB, PS4RF_TARGET_WIRED, 1, 0},
    {"sync.barrier.destroy", "sync", "", "", PS4RF_ROUTE_STUB, PS4RF_TARGET_WIRED, 1, 0},
    {"sync.barrier.release", "sync", "", "", PS4RF_ROUTE_STUB, PS4RF_TARGET_WIRED, 1, 0},
    {"sync.barrier.wait", "sync", "", "", PS4RF_ROUTE_STUB, PS4RF_TARGET_WIRED, 1, 0},
    {"sync.gate.arrive", "sync", "", "", PS4RF_ROUTE_STUB, PS4RF_TARGET_WIRED, 1, 0},
    {"sync.gate.create", "sync", "", "", PS4RF_ROUTE_STUB, PS4RF_TARGET_WIRED, 1, 0},
    {"sync.gate.destroy", "sync", "", "", PS4RF_ROUTE_STUB, PS4RF_TARGET_WIRED, 1, 0},
    {"sync.gate.release", "sync", "", "", PS4RF_ROUTE_STUB, PS4RF_TARGET_WIRED, 1, 0},
    {"sync.gate.status", "sync", "", "", PS4RF_ROUTE_STUB, PS4RF_TARGET_WIRED, 1, 0},
    {"sync.gate.wait", "sync", "", "", PS4RF_ROUTE_STUB, PS4RF_TARGET_WIRED, 1, 0},
    {"telemetry.read", "telemetry", "", "", PS4RF_ROUTE_STUB, PS4RF_TARGET_WIRED, 0, 1},
    {"verify.kernel.copyout", "verify", "", "provider state DEFERRED; W8 wires no privileged provider", PS4RF_ROUTE_DEFERRED_PRIVILEGE, PS4RF_TARGET_DEFERRED, 0, 0},
    {"verify.kernel.exec", "verify", "", "provider state DEFERRED; W8 wires no privileged provider", PS4RF_ROUTE_DEFERRED_PRIVILEGE, PS4RF_TARGET_DEFERRED, 0, 0},
    {"verify.kernel.read", "verify", "", "provider state DEFERRED; W8 wires no privileged provider", PS4RF_ROUTE_DEFERRED_PRIVILEGE, PS4RF_TARGET_DEFERRED, 0, 0},
    {"verify.samu.access", "verify", "", "provider state DEFERRED; W8 wires no privileged provider", PS4RF_ROUTE_DEFERRED_PRIVILEGE, PS4RF_TARGET_DEFERRED, 0, 0},
    {"verify.userland.exec", "verify", "", "provider state DEFERRED; needs the host verification->grant chain", PS4RF_ROUTE_DEFERRED_HOST_CHAIN, PS4RF_TARGET_DEFERRED, 0, 0},
};

static const ps4rf_arg_row PS4RF_ARG_TABLE[PS4RF_ARG_ROW_COUNT] = {
    {"slot", PS4RF_T_INT, 1},  /* ccp.submit */
    {"command", PS4RF_T_STR, 1},  /* ccp.submit */
    {"data", PS4RF_T_REF, 0},  /* ccp.submit */
    {"ir_sha256", PS4RF_T_HEX32, 1},  /* experiment.load */
    {"gvm_id", PS4RF_T_INT, 1},  /* gpuvm.lookup */
    {"va", PS4RF_T_INT, 1},  /* gpuvm.lookup */
    {"gvm_id", PS4RF_T_INT, 1},  /* gpuvm.map */
    {"va", PS4RF_T_INT, 1},  /* gpuvm.map */
    {"size", PS4RF_T_INT, 1},  /* gpuvm.map */
    {"prot", PS4RF_T_STR, 1},  /* gpuvm.map */
    {"mapping", PS4RF_T_REF, 1},  /* gpuvm.unmap */
    {"command", PS4RF_T_INT, 1},  /* ioctl.invoke */
    {"blob", PS4RF_T_STR, 1},  /* ioctl.invoke */
    {"mode", PS4RF_T_INT, 0},  /* ioctl.invoke */
    {"data", PS4RF_T_STR, 0},  /* ioctl.invoke */
    {"region_index", PS4RF_T_INT, 1},  /* kernel.read */
    {"offset", PS4RF_T_INT, 1},  /* kernel.read */
    {"length", PS4RF_T_INT, 1},  /* kernel.read */
    {"range", PS4RF_T_STR, 1},  /* kernel.snapshot */
    {"addr", PS4RF_T_INT, 0},  /* kernel.snapshot */
    {"size", PS4RF_T_INT, 0},  /* kernel.snapshot */
    {"region_ref", PS4RF_T_STR, 0},  /* kernel.snapshot */
    {"expected_sha256", PS4RF_T_HEX32, 0},  /* kernel.snapshot */
    {"recipe_ref", PS4RF_T_STR, 1},  /* kernel.snapshot.recipe */
    {"indices", PS4RF_T_ARRAY, 0},  /* kernel.snapshot.recipe */
    {"slot", PS4RF_T_INT, 1},  /* keymgr.claim */
    {"claim", PS4RF_T_REF, 1},  /* keymgr.release */
    {"scope", PS4RF_T_STR, 0},  /* keymgr.snapshot */
    {"size", PS4RF_T_INT, 1},  /* memory.alloc */
    {"alignment", PS4RF_T_INT, 0},  /* memory.alloc */
    {"ref", PS4RF_T_REF, 1},  /* memory.free */
    {"release_gate", PS4RF_T_REF, 0},  /* mock.block */
    {"ref", PS4RF_T_REF, 0},  /* mock.free_fail */
    {"capability", PS4RF_T_STR, 1},  /* session.shutdown */
    {"parties", PS4RF_T_INT, 1},  /* sync.barrier.create */
    {"barrier", PS4RF_T_REF, 1},  /* sync.barrier.destroy */
    {"barrier", PS4RF_T_REF, 1},  /* sync.barrier.release */
    {"barrier", PS4RF_T_REF, 1},  /* sync.barrier.wait */
    {"timeout_ms", PS4RF_T_INT, 0},  /* sync.barrier.wait */
    {"gate", PS4RF_T_REF, 1},  /* sync.gate.arrive */
    {"parties", PS4RF_T_INT, 1},  /* sync.gate.create */
    {"gate", PS4RF_T_REF, 1},  /* sync.gate.destroy */
    {"gate", PS4RF_T_REF, 1},  /* sync.gate.release */
    {"gate", PS4RF_T_REF, 1},  /* sync.gate.status */
    {"gate", PS4RF_T_REF, 1},  /* sync.gate.wait */
    {"timeout_ms", PS4RF_T_INT, 0},  /* sync.gate.wait */
    {"addr", PS4RF_T_INT, 1},  /* verify.kernel.copyout */
    {"size", PS4RF_T_INT, 1},  /* verify.kernel.copyout */
    {"expected", PS4RF_T_STR, 1},  /* verify.kernel.copyout */
    {"probe", PS4RF_T_STR, 1},  /* verify.kernel.exec */
    {"arguments", PS4RF_T_OBJECT, 0},  /* verify.kernel.exec */
    {"addr", PS4RF_T_INT, 1},  /* verify.kernel.read */
    {"expected", PS4RF_T_STR, 1},  /* verify.kernel.read */
    {"probe", PS4RF_T_STR, 1},  /* verify.samu.access */
    {"probe", PS4RF_T_STR, 1},  /* verify.userland.exec */
    {"arguments", PS4RF_T_OBJECT, 0},  /* verify.userland.exec */
};

/* Argument slice [first, first+count) of PS4RF_ARG_TABLE for each operation. */
#define PS4RF_ARG_FIRST_CCP_SUBMIT 0u
#define PS4RF_ARG_COUNT_CCP_SUBMIT 3u
#define PS4RF_ARG_FIRST_EXPERIMENT_LOAD 3u
#define PS4RF_ARG_COUNT_EXPERIMENT_LOAD 1u
#define PS4RF_ARG_FIRST_GPUVM_LOOKUP 4u
#define PS4RF_ARG_COUNT_GPUVM_LOOKUP 2u
#define PS4RF_ARG_FIRST_GPUVM_MAP 6u
#define PS4RF_ARG_COUNT_GPUVM_MAP 4u
#define PS4RF_ARG_FIRST_GPUVM_UNMAP 10u
#define PS4RF_ARG_COUNT_GPUVM_UNMAP 1u
#define PS4RF_ARG_FIRST_IOCTL_INVOKE 11u
#define PS4RF_ARG_COUNT_IOCTL_INVOKE 4u
#define PS4RF_ARG_FIRST_KERNEL_DUMP_FULL 15u
#define PS4RF_ARG_COUNT_KERNEL_DUMP_FULL 0u
#define PS4RF_ARG_FIRST_KERNEL_READ 15u
#define PS4RF_ARG_COUNT_KERNEL_READ 3u
#define PS4RF_ARG_FIRST_KERNEL_SNAPSHOT 18u
#define PS4RF_ARG_COUNT_KERNEL_SNAPSHOT 5u
#define PS4RF_ARG_FIRST_KERNEL_SNAPSHOT_RECIPE 23u
#define PS4RF_ARG_COUNT_KERNEL_SNAPSHOT_RECIPE 2u
#define PS4RF_ARG_FIRST_KEYMGR_CLAIM 25u
#define PS4RF_ARG_COUNT_KEYMGR_CLAIM 1u
#define PS4RF_ARG_FIRST_KEYMGR_RELEASE 26u
#define PS4RF_ARG_COUNT_KEYMGR_RELEASE 1u
#define PS4RF_ARG_FIRST_KEYMGR_SNAPSHOT 27u
#define PS4RF_ARG_COUNT_KEYMGR_SNAPSHOT 1u
#define PS4RF_ARG_FIRST_MEMORY_ALLOC 28u
#define PS4RF_ARG_COUNT_MEMORY_ALLOC 2u
#define PS4RF_ARG_FIRST_MEMORY_FREE 30u
#define PS4RF_ARG_COUNT_MEMORY_FREE 1u
#define PS4RF_ARG_FIRST_MOCK_BLOCK 31u
#define PS4RF_ARG_COUNT_MOCK_BLOCK 1u
#define PS4RF_ARG_FIRST_MOCK_FREE_FAIL 32u
#define PS4RF_ARG_COUNT_MOCK_FREE_FAIL 1u
#define PS4RF_ARG_FIRST_MOCK_HANG 33u
#define PS4RF_ARG_COUNT_MOCK_HANG 0u
#define PS4RF_ARG_FIRST_MOCK_LEAK 33u
#define PS4RF_ARG_COUNT_MOCK_LEAK 0u
#define PS4RF_ARG_FIRST_SESSION_PING 33u
#define PS4RF_ARG_COUNT_SESSION_PING 0u
#define PS4RF_ARG_FIRST_SESSION_SHUTDOWN 33u
#define PS4RF_ARG_COUNT_SESSION_SHUTDOWN 1u
#define PS4RF_ARG_FIRST_SESSION_STATUS 34u
#define PS4RF_ARG_COUNT_SESSION_STATUS 0u
#define PS4RF_ARG_FIRST_SYNC_BARRIER_CREATE 34u
#define PS4RF_ARG_COUNT_SYNC_BARRIER_CREATE 1u
#define PS4RF_ARG_FIRST_SYNC_BARRIER_DESTROY 35u
#define PS4RF_ARG_COUNT_SYNC_BARRIER_DESTROY 1u
#define PS4RF_ARG_FIRST_SYNC_BARRIER_RELEASE 36u
#define PS4RF_ARG_COUNT_SYNC_BARRIER_RELEASE 1u
#define PS4RF_ARG_FIRST_SYNC_BARRIER_WAIT 37u
#define PS4RF_ARG_COUNT_SYNC_BARRIER_WAIT 2u
#define PS4RF_ARG_FIRST_SYNC_GATE_ARRIVE 39u
#define PS4RF_ARG_COUNT_SYNC_GATE_ARRIVE 1u
#define PS4RF_ARG_FIRST_SYNC_GATE_CREATE 40u
#define PS4RF_ARG_COUNT_SYNC_GATE_CREATE 1u
#define PS4RF_ARG_FIRST_SYNC_GATE_DESTROY 41u
#define PS4RF_ARG_COUNT_SYNC_GATE_DESTROY 1u
#define PS4RF_ARG_FIRST_SYNC_GATE_RELEASE 42u
#define PS4RF_ARG_COUNT_SYNC_GATE_RELEASE 1u
#define PS4RF_ARG_FIRST_SYNC_GATE_STATUS 43u
#define PS4RF_ARG_COUNT_SYNC_GATE_STATUS 1u
#define PS4RF_ARG_FIRST_SYNC_GATE_WAIT 44u
#define PS4RF_ARG_COUNT_SYNC_GATE_WAIT 2u
#define PS4RF_ARG_FIRST_TELEMETRY_READ 46u
#define PS4RF_ARG_COUNT_TELEMETRY_READ 0u
#define PS4RF_ARG_FIRST_VERIFY_KERNEL_COPYOUT 46u
#define PS4RF_ARG_COUNT_VERIFY_KERNEL_COPYOUT 3u
#define PS4RF_ARG_FIRST_VERIFY_KERNEL_EXEC 49u
#define PS4RF_ARG_COUNT_VERIFY_KERNEL_EXEC 2u
#define PS4RF_ARG_FIRST_VERIFY_KERNEL_READ 51u
#define PS4RF_ARG_COUNT_VERIFY_KERNEL_READ 2u
#define PS4RF_ARG_FIRST_VERIFY_SAMU_ACCESS 53u
#define PS4RF_ARG_COUNT_VERIFY_SAMU_ACCESS 1u
#define PS4RF_ARG_FIRST_VERIFY_USERLAND_EXEC 54u
#define PS4RF_ARG_COUNT_VERIFY_USERLAND_EXEC 2u

/* Argument check for one operation, driven by the frozen argument slices: every
 * required argument present, no unknown argument, every present argument of the
 * frozen type. Identical rules to tools/primitive_iface/validate.py. */
int ps4rf_arg_type_ok(const jval *v, unsigned char type);   /* native/target/ps4rf_router.c */

#if defined(__GNUC__)
#define PS4RF_GEN_UNUSED __attribute__((unused))
#else
#define PS4RF_GEN_UNUSED
#endif
static PS4RF_GEN_UNUSED int ps4rf_args_slice_ok(unsigned first, unsigned n, const jval *args)
{
    unsigned k;
    if (args == NULL || jval_kind(args) != JVAL_OBJECT) return 0;
    /* the argument slices are small; the count fit is checked by the caller */
    for (k = 0u; k < n; k++) {
        const ps4rf_arg_row *ar = &PS4RF_ARG_TABLE[first + k];
        const jval *v = jval_get(args, ar->name);
        if (v == NULL) {
            if (ar->required) return 0;
            continue;
        }
        if (!ps4rf_arg_type_ok(v, ar->type)) return 0;
    }
    for (k = 0u; k < (unsigned)jval_count(args); k++) {
        const char *key = jval_key_at(args, k);
        unsigned q;
        unsigned found = 0u;
        if (key == NULL) return 0;
        for (q = 0u; q < n; q++) {
            const char *an = PS4RF_ARG_TABLE[first + q].name;
            unsigned t = 0u;
            while (an[t] != '\0' && key[t] != '\0' && an[t] == key[t]) t++;
            if (an[t] == '\0' && key[t] == '\0') { found = 1u; break; }
        }
        if (!found) return 0;
    }
    return 1;
}

static PS4RF_GEN_UNUSED int ps4rf_optable_args_ok(unsigned row_index, const jval *args)
{
    switch (row_index) {
    case 0u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_CCP_SUBMIT, PS4RF_ARG_COUNT_CCP_SUBMIT, args);
    case 1u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_EXPERIMENT_LOAD, PS4RF_ARG_COUNT_EXPERIMENT_LOAD, args);
    case 2u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_GPUVM_LOOKUP, PS4RF_ARG_COUNT_GPUVM_LOOKUP, args);
    case 3u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_GPUVM_MAP, PS4RF_ARG_COUNT_GPUVM_MAP, args);
    case 4u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_GPUVM_UNMAP, PS4RF_ARG_COUNT_GPUVM_UNMAP, args);
    case 5u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_IOCTL_INVOKE, PS4RF_ARG_COUNT_IOCTL_INVOKE, args);
    case 6u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_KERNEL_DUMP_FULL, PS4RF_ARG_COUNT_KERNEL_DUMP_FULL, args);
    case 7u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_KERNEL_READ, PS4RF_ARG_COUNT_KERNEL_READ, args);
    case 8u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_KERNEL_SNAPSHOT, PS4RF_ARG_COUNT_KERNEL_SNAPSHOT, args);
    case 9u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_KERNEL_SNAPSHOT_RECIPE, PS4RF_ARG_COUNT_KERNEL_SNAPSHOT_RECIPE, args);
    case 10u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_KEYMGR_CLAIM, PS4RF_ARG_COUNT_KEYMGR_CLAIM, args);
    case 11u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_KEYMGR_RELEASE, PS4RF_ARG_COUNT_KEYMGR_RELEASE, args);
    case 12u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_KEYMGR_SNAPSHOT, PS4RF_ARG_COUNT_KEYMGR_SNAPSHOT, args);
    case 13u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_MEMORY_ALLOC, PS4RF_ARG_COUNT_MEMORY_ALLOC, args);
    case 14u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_MEMORY_FREE, PS4RF_ARG_COUNT_MEMORY_FREE, args);
    case 15u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_MOCK_BLOCK, PS4RF_ARG_COUNT_MOCK_BLOCK, args);
    case 16u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_MOCK_FREE_FAIL, PS4RF_ARG_COUNT_MOCK_FREE_FAIL, args);
    case 17u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_MOCK_HANG, PS4RF_ARG_COUNT_MOCK_HANG, args);
    case 18u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_MOCK_LEAK, PS4RF_ARG_COUNT_MOCK_LEAK, args);
    case 19u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_SESSION_PING, PS4RF_ARG_COUNT_SESSION_PING, args);
    case 20u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_SESSION_SHUTDOWN, PS4RF_ARG_COUNT_SESSION_SHUTDOWN, args);
    case 21u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_SESSION_STATUS, PS4RF_ARG_COUNT_SESSION_STATUS, args);
    case 22u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_SYNC_BARRIER_CREATE, PS4RF_ARG_COUNT_SYNC_BARRIER_CREATE, args);
    case 23u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_SYNC_BARRIER_DESTROY, PS4RF_ARG_COUNT_SYNC_BARRIER_DESTROY, args);
    case 24u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_SYNC_BARRIER_RELEASE, PS4RF_ARG_COUNT_SYNC_BARRIER_RELEASE, args);
    case 25u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_SYNC_BARRIER_WAIT, PS4RF_ARG_COUNT_SYNC_BARRIER_WAIT, args);
    case 26u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_SYNC_GATE_ARRIVE, PS4RF_ARG_COUNT_SYNC_GATE_ARRIVE, args);
    case 27u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_SYNC_GATE_CREATE, PS4RF_ARG_COUNT_SYNC_GATE_CREATE, args);
    case 28u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_SYNC_GATE_DESTROY, PS4RF_ARG_COUNT_SYNC_GATE_DESTROY, args);
    case 29u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_SYNC_GATE_RELEASE, PS4RF_ARG_COUNT_SYNC_GATE_RELEASE, args);
    case 30u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_SYNC_GATE_STATUS, PS4RF_ARG_COUNT_SYNC_GATE_STATUS, args);
    case 31u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_SYNC_GATE_WAIT, PS4RF_ARG_COUNT_SYNC_GATE_WAIT, args);
    case 32u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_TELEMETRY_READ, PS4RF_ARG_COUNT_TELEMETRY_READ, args);
    case 33u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_VERIFY_KERNEL_COPYOUT, PS4RF_ARG_COUNT_VERIFY_KERNEL_COPYOUT, args);
    case 34u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_VERIFY_KERNEL_EXEC, PS4RF_ARG_COUNT_VERIFY_KERNEL_EXEC, args);
    case 35u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_VERIFY_KERNEL_READ, PS4RF_ARG_COUNT_VERIFY_KERNEL_READ, args);
    case 36u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_VERIFY_SAMU_ACCESS, PS4RF_ARG_COUNT_VERIFY_SAMU_ACCESS, args);
    case 37u: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_VERIFY_USERLAND_EXEC, PS4RF_ARG_COUNT_VERIFY_USERLAND_EXEC, args);
    default: return 0;
    }
}

#endif /* PS4RF_OPTABLE_DATA_H */
