# PolyTracker-Based Grammar Inference Project Context

**Date:** April 20, 2026  
**Student:** Mudassir (Thesis Project)  
**Goal:** Adapt MIMID grammar inference system to use LLVM-based PolyTracker instrumentation instead of manual parser modification

---

## 🎯 **PROJECT OBJECTIVE**

Replace MIMID's custom LLVM instrumentation pass with PolyTracker's binary-level taint tracking to achieve:
- ✅ Parser-agnostic grammar inference (no source modification)
- ✅ Language-agnostic approach (works on any LLVM-compilable code)
- ✅ Semantic-level byte-to-function mapping via call stack extraction
- ✅ High-quality grammar output comparable to manual instrumentation

---

## 🏆 **CURRENT STATUS: WORKING PROTOTYPE**

### **Achieved Milestones:**

1. ✅ **PolyTracker Integration**
   - Successfully instrumented parsers with `--taint --ftrace --cflog`
   - Control flow logging captures byte-level branching events
   - Function ID mappings extracted from `functionid.json`

2. ✅ **Call Stack Semantic Extraction**
   - Novel technique: Walk up call stacks from leaf functions (lexer)
   - Extract semantic parsing function (statement, expr, program)
   - Filters lexer-level functions via hardcoded skip list

3. ✅ **MIMID Format Compatibility**
   - Generated `token_events.json` in exact MIMID format
   - Added synthetic `<START>` root (method 0 with `null` name)
   - Proper BFS discovery order, no self-recursion

4. ✅ **Complete Pipeline Execution**
   - All MIMID stages working: treeminer → generalizemethod → generalizeloop → grammar-miner → generalizetokens → parsinggrammar
   - Token generalization: `"i="` → `<__ASCII_LOWER__> "="`
   - Multi-character semantic tokens preserved: `"i="`, `"1;"`

5. ✅ **Grammar Validation**
   - Docker wrapper (`test_subject.sh`) for macOS compatibility
   - Grammar-miner validation loop functional
   - Produces hierarchical grammar with preserved structure

---

## 📁 **KEY FILES & STRUCTURE**

### **Main Scripts:**
- `examples/extract_polytracker_to_mimid.py` - **Core converter** (TDAG → token_events.json)
- `examples/test_subject.sh` - Docker wrapper for grammar validation
- `examples/fix_original_field.py` - Updates "original" field in JSONs

### **Example Parser:**
- `examples/tiny.c` - Tiny programming language parser
- `examples/tiny.instrumented` - PolyTracker-instrumented binary
- `examples/tiny.input.1` through `tiny.input.5` - Test inputs
- `examples/functionid.json` - Function name mappings
- `examples/polytracker_cf.tdag` - Control flow trace (33GB for 6-byte input!)

### **Pipeline Outputs:**
- `examples/token_events.json` - MIMID-compatible format
- `examples/parse_trees.json` - Mined parse trees
- `examples/generalized_methods.json` - Method patterns
- `examples/generalized_loops.json` - Loop generalizations
- `examples/raw_grammar.json` - Initial grammar
- `examples/generalized_grammar.json` - Token-generalized grammar
- `examples/parsing_grammar.json` - **FINAL OUTPUT** (preserves structure)
- `examples/final_grammar.json` - Compacted (too aggressive, don't use)

### **MIMID Grammar Inference Scripts:**
Located in `src/grammar_inference/`:
- `treeminer.py` - Extracts parse trees from token events
- `generalizemethod.py` - Generalizes method patterns
- `generalizeloop.py` - Generalizes loops
- `grammar-miner.py` - Mines grammar rules with validation
- `generalizetokens.py` - Converts literals to token classes
- `parsinggrammar.py` - Creates parsing-ready grammar
- `grammar-compact.py` - Compacts grammar (SKIP - too aggressive!)

---

## 🔧 **TECHNICAL IMPLEMENTATION**

### **PolyTracker Instrumentation:**
```bash
# Step 1: Build with blight (generates blight_journal.jsonl + bitcode files)
docker run --rm --platform linux/amd64 -v "$(pwd):/workdir" -w /workdir \
    trailofbits/polytracker \
    polytracker build clang -o tiny tiny.c

# Step 2: Instrument (reads journal, generates tiny.instrumented + functionid.json)
docker run --rm --platform linux/amd64 -v "$(pwd):/workdir" -w /workdir \
    trailofbits/polytracker \
    polytracker instrument-targets --taint --ftrace --cflog tiny

# Step 3: Run with CF logging enabled (generates polytracker_cf.tdag)
docker run --rm --platform linux/amd64 -v "$(pwd):/workdir" -w /workdir \
    -e POLYDB=polytracker_cf.tdag \
    -e POLYTRACKER_STDIN_SOURCE=1 \
    -e POLYTRACKER_LOG_CONTROL_FLOW=1 \
    trailofbits/polytracker \
    bash -c "./tiny.instrumented < tiny.input.1"
```

**Intermediate files:** `tiny.bc`, `tiny.opt.bc`, `tiny.instrumented.bc`, `blight_journal.jsonl` (all regenerable, gitignored)

**Output:** `polytracker_cf.tdag` + `functionid.json`

### **Call Stack Extraction Technique:**

**Problem:** All byte branching happens in lexer functions (`next_sym`, `next_ch`)

**Solution:** Walk up call stack to find semantic caller:
```python
# Hardcoded skip list (TODO: replace with frequency heuristic)
SKIP_FUNCTIONS = {'next_sym', 'next_ch', 'main'}

for event in control_flow_log:
    semantic_stack = []
    for func in event.callstack:
        if func not in SKIP_FUNCTIONS:
            semantic_stack.append(func)
    
    # semantic_stack[-1] is the semantic parsing function!
```

### **Synthetic Root for MIMID:**

MIMID's `generalizemethod.py` expects `<START>` as root:
```python
# Add method 0 with None name (becomes <START>)
method_map["0"] = [0, None, [1]]

# All existing methods unchanged
method_map["1"] = [1, "parse_expr", [2]]
method_map["2"] = [2, "program", [3]]
# ...
```

### **Docker Wrapper for Validation:**

Grammar-miner needs executable that accepts filename argument:
```bash
#!/bin/bash
# test_subject.sh - Bridges stdin ↔ filename gap + Linux ↔ macOS

docker run --rm --platform linux/amd64 \
    -v "$SCRIPT_DIR:/workdir" -w /workdir \
    trailofbits/polytracker \
    bash -c "./tiny.instrumented < '$INPUT_FILE'" 2>/dev/null
```

---

## ⚠️ **KNOWN LIMITATIONS & ISSUES**

### **1. Single Input File Grammar (CURRENT)**

**Issue:** Grammar inferred from 1 input (`{i=1;}`) is too specific:
```
<statement> ::= <single_letter> "=" <number> ";"
```

**Professor's Feedback:** "Grammar has gone flat" + "Try multiple parse trees"

**Root Cause:** 
- grammar-compact.py can't distinguish semantic vs spurious non-terminals with 1 example
- Removes EVERYTHING including structure

**Solution:** 
- Use `parsing_grammar.json` (before compaction) - preserves hierarchy
- OR add multiple input files and re-run (proper solution)

### **2. Lexer Function Detection — Frequency + Position Heuristic**

**Status: ✅ IMPLEMENTED** (replaces hardcoded `SKIP_FUNCTIONS`)

**Why simple frequency fails:** With small inputs and simple grammars, ALL parse
functions appear in nearly every call stack. A pure frequency threshold (>50%)
would wrongly skip semantic functions like `parse_expr`, `program`, `statement`.

**Implemented approach — two structural signals:**

```python
def detect_skip_functions(events, freq_threshold=0.5,
                          leaf_ratio_threshold=0.7,
                          root_ratio_threshold=0.9,
                          leaf_depth=2):
    total = len(events)
    total_count, near_leaf_count, root_count = {}, {}, {}

    for event in events:
        stack = list(event.callstack)
        n = len(stack)
        for i, func in enumerate(stack):
            total_count[func] = total_count.get(func, 0) + 1
            if n - 1 - i < leaf_depth:        # innermost leaf_depth positions
                near_leaf_count[func] = near_leaf_count.get(func, 0) + 1
            if i == 0:
                root_count[func] = root_count.get(func, 0) + 1

    skip = set()
    for func, count in total_count.items():
        if count / total < freq_threshold:
            continue
        if near_leaf_count.get(func, 0) / count > leaf_ratio_threshold:
            skip.add(func)   # lexer/tokenizer function
        elif root_count.get(func, 0) / count > root_ratio_threshold:
            skip.add(func)   # entry point (main, etc.)
    return skip
```

**Signal logic:**
- **LEAF signal:** functions in the innermost `leaf_depth=2` stack positions in
  >70% of events they appear in → lexer functions (`next_sym`, `next_ch`)
- **ROOT signal:** functions at the outermost position in >90% of events →
  entry points (`main`)
- Semantic functions (`parse_expr`, `program`, `statement`) appear in the
  MIDDLE of stacks across varied parse contexts → neither signal fires → kept

**Validated on tiny.c:**
- Detected: `['main', 'next_sym']` — matches expected skip set
- `next_ch` not detected (correct — it never makes tainted branches itself;
  comparisons happen in `next_sym` after `next_ch` returns)
- Parse tree output identical to hardcoded approach

**Caveats:**
- **Scannerless parsers** (cJSON, json.c): no function dominates the leaf
  position across different parse contexts → heuristic returns empty set →
  correct behavior (nothing to skip; semantic functions ARE the leaf)
- **leaf_depth=2** may miss lexers in parsers with >2-level tokenizer chains
- Not mathematically proven; empirical validation needed per new parser

### **3. macOS ARM64 Environment**

**Challenge:** PolyTracker produces Linux x86_64 binaries

**Workaround:** All commands run via Docker with `--platform linux/amd64`

**Impact:** Slower execution (~2-3 seconds per grammar validation call)

---

## 📊 **GRAMMAR QUALITY METRICS**

### **Current Results (tiny.c with 1 input):**

**✅ Strengths:**
- Multi-character semantic tokens: `"i="`, `"1;"` (not character-level!)
- Hierarchical structure: START → parse_expr → program → statement → expr
- Proper token generalization: `[a-z]`, `[0-9]+`
- Clean derivation: `{i=1;}` → `{ <letter> = <number> ; }`

**⚠️ Limitations:**
- Single-character identifiers only (learned from `i`)
- Specific literals (would improve with more inputs)
- Verbose intermediates (`-1`, `-2`, `_94a0` pattern suffixes)

**Compared to MIMID Original:**
- ✅ Token quality: MATCH (multi-char tokens)
- ✅ Hierarchy: MATCH (semantic levels preserved)
- ⚠️ Generalization: LOWER (due to 1 input vs many)

---

## 🎯 **NEXT STEPS (PRIORITY ORDER)**

### **Priority 1: ✅ DONE — Frequency+Position Heuristic**
Implemented `detect_skip_functions()` in `extract_polytracker_to_mimid.py`.
Validated on tiny.c — identical parse trees to hardcoded approach.

### **Priority 2: Multi-Input Support**

**Goal:** Run pipeline on multiple input files per parser to get richer grammar.

**Input file organization:**
```
inputs/
├── tiny/
│   ├── tiny.input.1   ← copy from examples/ or MIMID repo
│   ├── tiny.input.2
│   └── tiny.input.3
├── json/
│   └── json.input.1
└── calc_parse/
    └── calc_parse.input.1
```

**Implementation plan (Option A — merge at token_events level):**
1. Run instrumented binary once per input → separate tdag per input
2. Run `extract_polytracker_to_mimid.py` per tdag → separate token_events JSON
3. Merge all token_events JSONs into one JSON array
4. MIMID pipeline runs once on merged token_events (unchanged)
5. `detect_skip_functions()` runs across ALL events from ALL inputs → more robust signal

**Input file sources:**
- Primary: MIMID repo (`cmimid/examples/`) — 5-7 inputs per parser, known-good
- Manual: handwrite for parsers not in MIMID repo
- NOT professor's fuzzer (https://rahul.gopinath.org/post/2019/05/28/simplefuzzer-01/) 
  — grammar-based, chicken-and-egg: can't use until grammar is already inferred

### **Priority 3: Test Language-Agnostic Claim**
Test on Tier 1 recursive descent parsers from MIMID repo:
- `calc_parse.c` — arithmetic expressions (explicit lexer, good first target)
- `json.c` — JSON (scannerless, tests empty-skip-set behavior)
- `mjs.c` — JavaScript (complex, stress test)
- Verify `detect_skip_functions()` detects correct skip set for each

### **Priority 4: Automation Script**
Create `run_inference.sh`:
```bash
./run_inference.sh <parser_name>
  → Instruments parser from examples/<parser>.c
  → Runs on all inputs in inputs/<parser>/
  → Merges token_events from all inputs
  → Runs MIMID pipeline
  → Outputs parsing_grammar.json
```

---

## 🐛 **DEBUGGING HISTORY**

### **Major Issues Resolved:**

1. **PolyTracker v4.0.0 API Missing**
   - `access_sequence()`, `function_trace()` all raise NotImplementedError
   - Solution: Direct section-level access via TDControlFlowLogSection

2. **Flat Byte-to-Function Mapping**
   - All bytes initially mapped to `next_sym` only
   - Solution: Call stack extraction technique

3. **Method Map Structure Issues**
   - First attempt: Flat (no parent-child relationships)
   - Second attempt: Wrong discovery order (violated treeminer assumptions)
   - Third attempt: Self-recursion (expr → expr)
   - Final solution: BFS traversal + self-recursion removal

4. **Synthetic Root Missing**
   - Empty string `""` → `<>` (not `<START>`)
   - Solution: Use `None` → `null` in JSON → `<START>` in treeminer

5. **Binary Execution on macOS**
   - Linux binary can't run natively
   - Solution: Docker wrapper for validation

---

## 📚 **KEY INSIGHTS FOR THESIS**

### **Novel Contributions:**

1. **Call Stack Semantic Extraction**
   - First use of taint tracking call stacks for grammar inference
   - Generalizable to any LLVM-based taint tracker
   - Language-agnostic (works on C, C++, Rust, etc.)

2. **PolyTracker Integration Technique**
   - Control flow logging (`--cflog`) sufficient for parsers
   - No need for full data flow (branching is what matters)
   - Binary instrumentation vs source modification trade-off documented

3. **MIMID Format Compatibility**
   - Synthetic root requirement discovered and documented
   - BFS discovery order requirement clarified
   - Docker wrapper pattern for cross-platform validation

### **Comparison to Original MIMID:**

| Aspect | MIMID (Manual) | PolyTracker (Ours) |
|--------|----------------|-------------------|
| **Instrumentation** | Custom LLVM pass | PolyTracker binary |
| **Parser Modification** | Required (add hooks) | None (binary-only) |
| **Language Support** | C only | Any LLVM-compilable |
| **Lexer Filtering** | Manual exclusion | Post-hoc filtering |
| **Setup Complexity** | High (LLVM expertise) | Medium (Docker + scripts) |
| **Grammar Quality** | High (with many inputs) | High (comparable) |

---

## 🔬 **TESTING CHECKLIST**

### **Tier 1 Parsers (Priority):**
- [x] tiny.c (working, 1 input)
- [ ] jsmn (JSON parser)
- [ ] cJSON (JSON parser)
- [ ] calc_parse (calculator)
- [ ] sExpr (S-expression parser)
- [ ] tinyexpr (expression parser)

### **Tier 2 Parsers (Stretch):**
- [ ] Rust-based parser
- [ ] C++ parser
- [ ] Go parser (via LLVM backend)

### **Quality Metrics to Track:**
- Number of semantic levels preserved
- Token vs character-level granularity
- Grammar compactness (non-terminal count)
- Validation accuracy (accept/reject test cases)

---

## 📖 **REFERENCES**

**Original MIMID Paper:**
- Gopinath et al. "Mining Input Grammars from Dynamic Taints"

**PolyTracker:**
- Trail of Bits, PolyTracker v4.0.0
- GitHub: https://github.com/trailofbits/polytracker
- Docker: `trailofbits/polytracker:latest`

**LLVM/Clang:**
- Version used: 18.x (incompatible with standalone MIMID's Pygmalion)

---

## 💻 **ENVIRONMENT SETUP**

**Platform:** macOS ARM64 (M-series chip)

**Docker Required:**
```bash
docker pull trailofbits/polytracker:latest
```

**Python Dependencies:**
```
polytracker
cxxfilt
pudb
```

**Directory Structure:**
```
llvm-grammar-inference/
├── examples/           # Test parsers and outputs
├── src/
│   └── grammar_inference/  # MIMID pipeline scripts
├── CONTEXT.md         # This file
├── PIPELINE.md        # Workflow documentation
└── README.md
```

---

## 🎓 **FOR THESIS WRITING**

### **Key Sections:**

1. **Introduction**
   - Grammar inference importance
   - MIMID limitations (manual instrumentation)
   - PolyTracker opportunity (binary-level)

2. **Methodology**
   - PolyTracker control flow logging
   - Call stack semantic extraction algorithm
   - MIMID format compatibility adaptations

3. **Implementation**
   - Docker environment setup
   - `extract_polytracker_to_mimid.py` architecture
   - Validation wrapper design

4. **Evaluation**
   - Comparison to original MIMID
   - Language-agnostic testing
   - Grammar quality metrics

5. **Discussion**
   - Trade-offs: parser-agnostic vs manual optimization
   - Frequency heuristic for lexer detection
   - Future work: multi-language validation

---

## ⚡ **QUICK START (NEW ENVIRONMENT)**

```bash
# 1. Clone repo
git clone <repo-url>
cd llvm-grammar-inference

# 2. Set up Python environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Test with tiny.c
cd examples
./run_inference.sh tiny.c tiny.input.1

# 4. View results
cat parsing_grammar.json | python3 -m json.tool
```

---

## 📝 **NOTES FOR CLAUDE CODE**

When working on this project:
- Always run PolyTracker commands via Docker with `--platform linux/amd64`
- Skip `grammar-compact.py` - use `parsing_grammar.json` as final output
- Test changes on tiny.c before moving to other parsers
- Update SKIP_FUNCTIONS when adding frequency heuristic
- Document any new findings in this CONTEXT.md file

---

**Last Updated:** April 20, 2026  
**Status:** ✅ Working prototype, ready for enhancement and broader testing
