# zoxy — zero-allocation L4/L7 edge proxy (design)

An L4/L7 edge proxy in the spirit of Envoy/Linkerd, written in Zig 0.16 with 
a hard constraint: **nothing allocates on the hot path.** Steady-state 
operation issues zero heap allocations and zero allocating syscalls.
