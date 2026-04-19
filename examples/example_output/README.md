# Example Pipeline Outputs

These are example outputs from running the complete pipeline on tiny.c with input `{i=1;}`.

**Input:** `tiny.input.1` = `{i=1;}`

**Files:**
- `token_events.json` - MIMID-compatible format after PolyTracker extraction
- `parse_trees.json` - Mined parse trees from treeminer.py
- `parsing_grammar.json` - Final grammar (use this, not final_grammar.json)

**To regenerate:**
```bash
cd examples
# Follow PIPELINE.md steps 1-11
```

**Note:** These are for reference only. Your outputs may differ slightly depending on PolyTracker version.
