#!/usr/bin/env python3
"""
Fix 'original' field in MIMID pipeline JSON files

Changes "original": "polytracker_cflog" to "original": "./test_subject.sh"
so that grammar-miner can execute the parser for validation.

Usage:
    python3 fix_original_field.py

Updates:
    - token_events.json
    - parse_trees.json
    - generalized_methods.json
    - generalized_loops.json (if exists)
"""

import json
import os
import sys

FILES_TO_FIX = [
    'token_events.json',
    'parse_trees.json',
    'generalized_methods.json',
    'generalized_loops.json'
]

NEW_ORIGINAL = './test_subject.sh'

print("="*70)
print("FIXING 'original' FIELD FOR GRAMMAR-MINER")
print("="*70)

fixed_count = 0
for filename in FILES_TO_FIX:
    if not os.path.exists(filename):
        print(f"\n⚠️  Skipping {filename} (not found)")
        continue
    
    print(f"\nProcessing {filename}...")
    
    # Load JSON
    with open(filename, 'r') as f:
        data = json.load(f)
    
    # Fix all entries
    if isinstance(data, list):
        for entry in data:
            if 'original' in entry:
                old_value = entry['original']
                entry['original'] = NEW_ORIGINAL
                print(f"  '{old_value}' → '{NEW_ORIGINAL}'")
    
    # Save back
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"  ✓ Updated {filename}")
    fixed_count += 1

print(f"\n{'='*70}")
print(f"✓ Fixed {fixed_count} file(s)")
print(f"{'='*70}")

print(f"\nNext steps:")
print(f"  1. Make wrapper executable: chmod +x test_subject.sh")
print(f"  2. Test wrapper: ./test_subject.sh tiny.input.1")
print(f"  3. Continue pipeline: python3 ../src/grammar_inference/grammar-miner.py generalized_loops.json > raw_grammar.json")
