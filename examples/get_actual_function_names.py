#!/usr/bin/env python3
"""Use read_string() method to extract actual function names"""

from polytracker import PolyTrackerTrace
from polytracker.taint_dag import TDFunctionsSection, TDStringSection, TDEventsSection
import json

print("Loading TDAG...")
trace = PolyTrackerTrace.load("polytracker.tdag")
tdfile = trace.tdfile

# Get sections
functions_section = None
string_section = None
events_section = None

for section in tdfile.sections:
    if isinstance(section, TDFunctionsSection):
        functions_section = section
    elif isinstance(section, TDStringSection):
        string_section = section
    elif isinstance(section, TDEventsSection):
        events_section = section

print("\n" + "="*60)
print("EXTRACTING FUNCTION NAMES USING read_string()")
print("="*60)

function_id_to_name = {}

if functions_section and string_section:
    print(f"✓ Found both sections")
    print(f"\nTrying read_string() method...")
    
    for func_id, fn_header in enumerate(functions_section):
        name_offset = fn_header.name_offset
        
        try:
            # Call read_string with the offset
            func_name = string_section.read_string(name_offset)
            
            if func_name:
                function_id_to_name[func_id] = func_name
                print(f"  ✓ Function {func_id}: '{func_name}' (offset: {name_offset})")
            else:
                function_id_to_name[func_id] = f"func_{func_id}"
                print(f"  ⚠ Function {func_id}: read_string returned empty (offset: {name_offset})")
        
        except Exception as e:
            function_id_to_name[func_id] = f"func_{func_id}"
            print(f"  ✗ Function {func_id}: Error - {e} (offset: {name_offset})")
        
        if func_id >= 15:
            break

print(f"\n✓ Total functions: {len(function_id_to_name)}")

# Now check if we got the parsing functions from tiny.c
expected_functions = ['program', 'statement', 'expr', 'test', 'sum', 'term']
found_expected = []

for func_name in function_id_to_name.values():
    if any(exp in func_name.lower() for exp in expected_functions):
        found_expected.append(func_name)

if found_expected:
    print(f"\n🎉 FOUND PARSING FUNCTIONS: {found_expected}")
else:
    print(f"\n⚠️  Did not find expected parsing functions")
    print(f"   Expected: {expected_functions}")
    print(f"   Got: {list(function_id_to_name.values())[:10]}")

# Generate final output
print("\n" + "="*60)
print("GENERATING FINAL MIMID OUTPUT")
print("="*60)

# Load input
with open('tiny.input.1', 'rb') as f:
    input_bytes = f.read()
with open('tiny.input.1', 'r') as f:
    inputstr = f.read()

# Get source nodes
forest = trace.taint_forest
source_nodes = {}

for node in forest.nodes():
    if hasattr(node, 'source') and node.source is not None:
        try:
            offset_obj = trace.file_offset(node)
            if offset_obj:
                offset = offset_obj.offset
                source_nodes[offset] = {
                    'node': node,
                    'label': node.label,
                    'affected_cf': node.affected_control_flow
                }
        except:
            pass

# Build method_map
method_map = {}
for func_id, func_name in function_id_to_name.items():
    method_map[str(func_id + 1)] = [func_id + 1, func_name, []]

# Build comparisons
comparisons = []
for offset in sorted(source_nodes.keys()):
    if offset < len(input_bytes):
        byte_val = input_bytes[offset]
        char = chr(byte_val) if byte_val < 128 else f'\\x{byte_val:02x}'
        # Still use default function since we can't correlate
        comparisons.append([offset, char, 1])

output = [{
    'comparisons_fmt': 'idx, char, method_call_id',
    'comparisons': comparisons,
    'method_map_fmt': 'method_call_id, method_name, children',
    'method_map': method_map,
    'inputstr': inputstr,
    'original': 'polytracker_final_with_real_names',
    'arg': 'input'
}]

with open('token_events_FINAL.json', 'w') as f:
    json.dump(output, f, indent=2)

print(f"\n✓ Created token_events_FINAL.json")
print(f"  Comparisons: {len(comparisons)}")
print(f"  Functions in method_map: {len(method_map)}")

# Print summary
print("\n" + "="*60)
print("SUMMARY")
print("="*60)
print(f"""
Input: {repr(inputstr)}
Bytes tracked: {len(source_nodes)}
Functions identified: {len(function_id_to_name)}

Next steps:
1. ✅ We have real function names (if read_string worked)
2. ⚠️  All bytes map to first function (API limitation)
3. 🎯 Ready to post GitHub issue with findings
4. 🎯 Test with MIMID pipeline to validate approach
""")