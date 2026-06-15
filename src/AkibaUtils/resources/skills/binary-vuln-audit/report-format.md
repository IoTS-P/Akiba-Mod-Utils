# Final Report Format

Use this structure:

## Summary

2-4 sentences covering:

- binary purpose if discoverable;
- total distinct findings;
- highest severity;
- overall confidence;
- approximate coverage.

## Coverage Report

Include:

- total functions observed;
- functions analyzed in detail;
- functions shallow-reviewed;
- skipped functions and reasons;
- chunks completed.

## Findings

For each distinct issue:

### F<N>. <short title>

- Location: `<function name> @ <address>`
- Class: stack buffer overflow / format string / heap overflow / UAF / double free / integer overflow / etc.
- Evidence: minimal asm or pseudocode excerpt, plus which argument/data is attacker-controlled.
- Reachability: concrete call chain or xrefs from entry-point-reachable code.
- Impact: code execution / information leak / DoS / privilege escalation.
- Severity: Critical / High / Medium / Low with rationale.
- Notes: relevant durable comment addresses or follow-up tasks.

If no reachable vulnerability is found, state that clearly. Do not invent speculative findings.
