#!/usr/bin/env python3
"""
PolyTracker to MIMID Format Converter
======================================

Extracts control-flow byte-to-function mappings from PolyTracker TDAG traces
and converts them to MIMID-compatible token_events.json format.

Requirements:
  - polytracker_cf.tdag (generated with --cflog flag)
  - functionid.json (generated during instrumentation)
  - tiny.input.1 (or your input file)

Output:
  - token_events.json (MIMID format, ready for treeminer.py)

Usage:
  python3 extract_polytracker_to_mimid.py

Author: Mudassir (PolyTracker + MIMID Integration)
Date: March 4, 2026
"""

import json
import cxxfilt
from polytracker import PolyTrackerTrace
from polytracker.taint_dag import (
    TDControlFlowLogSection,
    TDTaintedControlFlowEvent,
    TDSourceNode,
    TDUnionNode,
    TDRangeNode,
)
from collections import deque

# Configuration
TDAG_FILE = "polytracker_cf.tdag"
FUNCTION_MAP_FILE = "functionid.json"
INPUT_FILE = "tiny.input.1"
OUTPUT_FILE = "token_events.json"

# Lexer-level functions to skip (parser-specific)
# TODO: Replace with frequency-based auto-detection
SKIP_FUNCTIONS = {'next_sym', 'next_ch', 'main'}

print("="*70)
print("POLYTRACKER → MIMID CONVERTER")
print("="*70)

# Load trace
print(f"\n[1/5] Loading TDAG: {TDAG_FILE}")
trace = PolyTrackerTrace.load(TDAG_FILE)
tdfile = trace.tdfile
print("  ✓ Trace loaded successfully")

# Load control flow log
print(f"\n[2/5] Loading control flow events...")
cflog = tdfile._get_section(TDControlFlowLogSection)
print("  ✓ Control flow log section found")

# Load function names
print(f"\n[3/5] Loading function mappings: {FUNCTION_MAP_FILE}")
with open(FUNCTION_MAP_FILE) as f:
    funcnames = list(map(cxxfilt.demangle, json.load(f)))
cflog.function_id_mapping(funcnames)
print(f"  ✓ Loaded {len(funcnames)} function names")

def create_synthetic_root(method_map, comparisons):
    """
    Add synthetic <START> root node for MIMID compatibility.
    
    MIMID's generalizemethod.py expects all parse trees to have a 
    synthetic <START> root with NULL name. This function adds method 0
    with an empty name (which becomes <START> in treeminer) that points
    to the existing root (method 1).
    
    All existing method IDs and comparisons remain UNCHANGED.
    
    Before:
      1: parse_expr → [2]
      2: program → [3]
      
    After:
      0: "" → [1]           ← NEW: Synthetic root (becomes <START>)
      1: parse_expr → [2]   ← UNCHANGED
      2: program → [3]      ← UNCHANGED
    """
    # Create new method_map with synthetic root prepended
    new_method_map = {}
    
    # Add synthetic root as method 0
    # Empty string name becomes <START> in treeminer
    # Points to method 1 (the original root: parse_expr)
    new_method_map["0"] = [0, None, [1]]
    
    # Copy all existing methods UNCHANGED
    for id_str, method_data in method_map.items():
        new_method_map[id_str] = method_data
    
    # Comparisons remain UNCHANGED - they still reference the same method IDs
    return new_method_map, comparisons

def resolve_label_to_input_offsets(label, tdfile):
    """
    Walk the taint DAG from a label back to source nodes,
    returning the set of input byte offsets.
    """
    offsets = set()
    seen = set()
    stack = [label]
    
    while stack:
        lbl = stack.pop()
        if lbl in seen:
            continue
        seen.add(lbl)
        
        node = tdfile.decode_node(lbl)
        
        if isinstance(node, TDSourceNode):
            offsets.add(node.offset)
        elif isinstance(node, TDUnionNode):
            stack.append(node.left)
            stack.append(node.right)
        elif isinstance(node, TDRangeNode):
            stack.extend(range(node.first, node.last + 1))
    
    return offsets

print(f"\n[4/5] Building call graph from control flow events...")

# Collect all semantic call stacks
all_stacks = []
byte_to_functions = {}
total_events = 0

for event in cflog:
    if isinstance(event, TDTaintedControlFlowEvent):
        total_events += 1
        input_offsets = resolve_label_to_input_offsets(event.label, tdfile)
        
        # Extract semantic stack (skip lexer-level functions)
        semantic_stack = []
        for func in event.callstack:
            if func not in SKIP_FUNCTIONS:
                semantic_stack.append(func)
        
        # Fallback if stack is empty after filtering
        if not semantic_stack:
            # Use first non-skipped function from original stack, or 'main'
            for func in event.callstack:
                if func != 'main':
                    semantic_stack = [func]
                    break
            if not semantic_stack:
                semantic_stack = ['main']
        
        all_stacks.append(semantic_stack)
        
        # Map bytes to their deepest (leaf) function
        for offset in input_offsets:
            if offset not in byte_to_functions:
                byte_to_functions[offset] = []
            byte_to_functions[offset].append(semantic_stack[-1])

print(f"  ✓ Processed {total_events} control flow events")
print(f"  ✓ Found {len(all_stacks)} semantic call stacks")
print(f"  ✓ Mapped {len(byte_to_functions)} input bytes to functions")

# Build parent-child relationships (no self-recursion)
parent_child = {}

for stack in all_stacks:
    for i in range(len(stack) - 1):
        parent = stack[i]
        child = stack[i + 1]
        
        # Skip self-recursion (expr calling expr)
        if parent == child:
            continue
        
        if parent not in parent_child:
            parent_child[parent] = set()
        parent_child[parent].add(child)

print(f"\n  Call relationships (self-recursion removed):")
for parent, children in sorted(parent_child.items()):
    print(f"    {parent} → {sorted(children)}")

# Find root function
all_children = set()
for children in parent_child.values():
    all_children.update(children)

all_parents = set(parent_child.keys())
roots = all_parents - all_children

# Handle multiple or no roots
if len(roots) > 1:
    # Choose the one that appears first in stacks
    root = all_stacks[0][0] if all_stacks else sorted(roots)[0]
    print(f"\n  ⚠️  Multiple roots found: {sorted(roots)}")
    print(f"  ✓ Using: {root}")
elif len(roots) == 1:
    root = list(roots)[0]
    print(f"\n  ✓ Root function: {root}")
else:
    # No clear root, use first function in first stack
    root = all_stacks[0][0] if all_stacks else 'main'
    print(f"\n  ⚠️  No clear root found")
    print(f"  ✓ Using: {root}")

# Build method_map in DISCOVERY ORDER using BFS
# This ensures treeminer.py sees children after their parents
visited = set()
discovery_order = []
queue = deque([root])

while queue:
    func = queue.popleft()
    if func in visited:
        continue
    
    visited.add(func)
    discovery_order.append(func)
    
    # Add children to queue in sorted order (for determinism)
    if func in parent_child:
        for child in sorted(parent_child[func]):
            if child not in visited:
                queue.append(child)

# Include any functions from byte mappings not in tree
for funcs in byte_to_functions.values():
    for func in funcs:
        if func not in visited:
            discovery_order.append(func)
            visited.add(func)

print(f"\n  Discovery order (BFS from root): {discovery_order}")

# Assign method IDs in discovery order
func_to_id = {}
for idx, func in enumerate(discovery_order, start=1):
    func_to_id[func] = idx

# Build method_map
method_map = {}
for func in discovery_order:
    func_id = func_to_id[func]
    children = parent_child.get(func, set())
    
    # Get child IDs (only for children in our tree)
    child_ids = []
    for child in sorted(children):
        if child in func_to_id:
            child_ids.append(func_to_id[child])
    
    method_map[str(func_id)] = [func_id, func, child_ids]

# Validate: no self-references
print(f"\n[5/5] Validation checks...")
has_errors = False
for method_id, (id, name, children) in method_map.items():
    if id in children:
        print(f"  ✗ ERROR: {name} (id={id}) has itself as child!")
        has_errors = True

if not has_errors:
    print(f"  ✓ No self-references found")
    print(f"  ✓ All {len(method_map)} methods valid")

# Read input file
with open(INPUT_FILE, 'rb') as f:
    input_bytes = f.read()
with open(INPUT_FILE, 'r') as f:
    inputstr = f.read()

print(f"\n  Input file: {INPUT_FILE}")
print(f"  Input content: '{inputstr[:50]}{'...' if len(inputstr) > 50 else ''}'")
print(f"  Input length: {len(input_bytes)} bytes")

# Ensure ALL bytes are covered (fill gaps with root function)
for offset in range(len(input_bytes)):
    if offset not in byte_to_functions:
        byte_to_functions[offset] = [root]

# Build comparisons
comparisons = []
for offset in range(len(input_bytes)):
    if offset < len(input_bytes):
        byte_val = input_bytes[offset]
        char = chr(byte_val) if byte_val < 128 else f'\\x{byte_val:02x}'
        
        # Use most common function for this byte
        func_counts = {}
        for func in byte_to_functions.get(offset, [root]):
            func_counts[func] = func_counts.get(func, 0) + 1
        
        if func_counts:
            most_common = max(func_counts.items(), key=lambda x: x[1])[0]
            method_id = func_to_id.get(most_common, 1)
        else:
            method_id = 1  # Fallback to root
        
        comparisons.append([offset, char, method_id])

# Add synthetic <START> root for MIMID compatibility
print(f"\nAdding synthetic <START> root...")
method_map, comparisons = create_synthetic_root(method_map, comparisons)
print(f"  ✓ Method 0 (synthetic root) added")
print(f"  ✓ Existing methods unchanged")

# Generate output
output = [{
    'comparisons_fmt': 'idx, char, method_call_id',
    'comparisons': comparisons,
    'method_map_fmt': 'method_call_id, method_name, children',
    'method_map': method_map,
    'inputstr': inputstr,
    'original': 'polytracker_cflog',
    'arg': 'input'
}]

with open(OUTPUT_FILE, 'w') as f:
    json.dump(output, f, indent=2)

print(f"\n{'='*70}")
print("CONVERSION COMPLETE")
print("="*70)
print(f"\n✓ Output: {OUTPUT_FILE}")
print(f"  Format: MIMID-compatible token_events.json")
print(f"  Comparisons: {len(comparisons)} bytes")
print(f"  Functions: {len(method_map)} (including synthetic root)")
print(f"  Root: <START> (id=0, synthetic)")
print(f"  Parser entry: {root} (id=1, unchanged)")

print(f"\nFunction distribution:")
for method_id in sorted(method_map.keys(), key=lambda x: int(x)):
    id, name, children = method_map[method_id]
    if id == 0:
        # Synthetic root
        child_names = [method_map[str(c)][1] for c in children if str(c) in method_map]
        print(f"  <START> (synthetic root) → {child_names}")
    else:
        # Real methods
        count = sum(1 for c in comparisons if c[2] == id)
        child_names = [method_map[str(c)][1] for c in children if str(c) in method_map]
        child_str = f" → {child_names}" if child_names else ""
        print(f"  {name}: {count} bytes{child_str}")

print(f"\n{'='*70}")
print("NEXT STEPS")
print("="*70)
print(f"\n1. Run MIMID pipeline:")
print(f"   python3 ../src/grammar_inference/treeminer.py {OUTPUT_FILE} > parse_trees.json")
print(f"\n2. Continue with:")
print(f"   python3 ../src/grammar_inference/generalizemethod.py parse_trees.json > generalized_methods.json")
print(f"\n{'='*70}")