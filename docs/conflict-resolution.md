# Conflict resolution policy

Purpose: resolve disagreements across sources without forcing a merge when evidence is weak or contradictory.

## Deterministic precedence

For each field, the winner is chosen in this order:
1. Source priority by data domain: CMDB > ticketing > finance > HR, for operational asset data.
2. Recency: the most recent source snapshot wins when priorities are tied.
3. Confidence: the value with the higher field confidence wins if the timestamps are identical.
4. If all three are tied, keep both values and flag for manual review.

This preserves the losing values so they are still auditable.

## Worked examples

### Example 1: CMDB vs finance

- CMDB criticality = high
- Finance criticality = medium
- Both are for the same asset and share the same entity identity.
- Because CMDB has higher source priority for asset criticality, the canonical value becomes `high`.
- The finance value is preserved in `merge_history` and `source_refs` for later audit or review.

### Example 2: same entity, contradictory identity values

- CMDB serial = `SN-1001`
- Finance serial = `SN-1002`
- Any merge with distinct hard identifiers is blocked. The system records a hard conflict and retains the original records separately.

### Example 3: low-confidence candidate

- Name matches, but there is no confirming serial or identifier.
- The pair is never auto-merged if confidence is below the threshold.
- It moves to the manual review queue with a rationale and all evidence references.

## Implementation contract

The merge logic is intentionally conservative:
- hard conflicts block a merge
- transitive closure is only allowed across links above the minimum confidence threshold
- low-confidence links are not chained across multiple hops
- every winning and losing value is retained in merge history and source provenance

## Test contract

Ensure the following invariants hold:
- same name + different serial numbers does not merge
- higher-priority source wins on a disputed operational field
- recency resolves ties when priority is equal
- low-confidence candidates are not chained into a wider closure
