/* D3_lock_coverage fixtures: is a store covered by *a* lock on every path, or by none?
 *
 * Coverage used to be "does one lock block dominate the store".  Two arms that lock in
 * different blocks leave the join undominated even though every path holds a lock -- and
 * with the CFG correction those alternative paths exist.  Both directions are fixed here:
 *
 *   every_path   lock on both arms, store after the join   -> NO_CLAIM
 *   one_path     one arm locks, the other writes           -> UNLOCKED_WRITE
 */

    .intel_syntax noprefix
    .text

    .globl d3_lock
    .type d3_lock, @function
d3_lock:
    ret
    .size d3_lock, .-d3_lock

    .globl fixture_d3_lock_on_every_path
    .type fixture_d3_lock_on_every_path, @function
fixture_d3_lock_on_every_path:
    test rsi, rsi
    je 1f
    mov rdi, rbx
    call d3_lock
    jmp 2f
1:
    mov rdi, rbx
    call d3_lock
2:
    mov dword ptr [rbx + 0x110], 1
    ret
    .size fixture_d3_lock_on_every_path, .-fixture_d3_lock_on_every_path

    .globl fixture_d3_lock_on_one_path
    .type fixture_d3_lock_on_one_path, @function
fixture_d3_lock_on_one_path:
    test rsi, rsi
    je 3f
    mov rdi, rbx
    call d3_lock
    mov dword ptr [rbx + 0x110], 1
    jmp 4f
3:
    mov dword ptr [rbx + 0x110], 2
4:
    ret
    .size fixture_d3_lock_on_one_path, .-fixture_d3_lock_on_one_path

    /* Regression: lock call in same basic block must not hide an earlier store. */
    .globl fixture_d3_store_before_lock_same_block
    .type fixture_d3_store_before_lock_same_block, @function
fixture_d3_store_before_lock_same_block:
    mov dword ptr [rbx + 0x110], 1
    mov rdi, rbx
    call d3_lock
    ret
    .size fixture_d3_store_before_lock_same_block, .-fixture_d3_store_before_lock_same_block

    /* Counterexample: identical block shape, store comes after the lock. */
    .globl fixture_d3_store_after_lock_same_block
    .type fixture_d3_store_after_lock_same_block, @function
fixture_d3_store_after_lock_same_block:
    mov rdi, rbx
    call d3_lock
    mov dword ptr [rbx + 0x110], 1
    ret
    .size fixture_d3_store_after_lock_same_block, .-fixture_d3_store_after_lock_same_block
