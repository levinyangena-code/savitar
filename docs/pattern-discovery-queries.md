# Pattern-Discovery Queries

Five documented Cypher queries against the Savitar schema.

- Schema labels: `Asset`, `Identity`, `Vulnerability`, `Actor`, `Incident`, `IOC`, `TTP`.
- Edge types: `affected_by`, `runs_on`, `authenticates_to`, `exploits`,
  `observed_on`, `attributed_to`, `targeted`, `contacted`, `uses_ttp`.

## 1. Related entities to an alert / IOC

```cypher
MATCH path = (ioc:IOC {id: $ioc_id})-[*1..3]-(n)
WHERE NONE(x IN nodes(path) WHERE size(filter(y IN nodes(path) WHERE y = x)) > 1)
WITH n, min(length(path)) AS depth,
     [r IN relationships(path) | r.evidence] AS evs
RETURN n.id AS entity_id, labels(n) AS types, depth,
       savitar.confidence(depth, evs) AS confidence,
       savitar.recency(max([e IN evs | e.timestamp])) AS recency,
       savitar.impact(n) AS impact,
       savitar.confidence(depth, evs)
         * savitar.recency(max([e IN evs | e.timestamp]))
         * savitar.impact(n) AS final
ORDER BY final DESC, entity_id ASC LIMIT 50;
```

Sample output for `ioc:sha256:deadbeef` — see `examples/sample_outputs.json`.

## 2. Recurring patterns in a business unit

```cypher
MATCH (a)-[r]->(b)
WHERE (a.business_unit = $bu OR b.business_unit = $bu)
  AND r.evidence.timestamp >= datetime() - duration({days: 30})
WITH labels(a)[0] AS srcT, type(r) AS rel, labels(b)[0] AS dstT, count(r) AS occ
WHERE occ >= 2
RETURN srcT + ' -[:' + rel + ']-> ' + dstT AS motif, occ, ...
ORDER BY precision DESC LIMIT 20;
```

## 3. Rank relationships by decision relevance

```cypher
UNWIND $entity_ids AS id
MATCH (n {id: id})
OPTIONAL MATCH (n)-[r]-(inc:Incident)
WITH n,
     savitar.confidence(0, collect(DISTINCT r.evidence)) AS confidence,
     savitar.recency(coalesce(max(r.evidence.timestamp), datetime())) AS recency,
     savitar.impact(n) AS impact
RETURN n.id, confidence, recency, impact,
       confidence * recency * impact AS final
ORDER BY final DESC, n.id ASC;
```

## 4. Prior incidents sharing the same TTPs

```cypher
MATCH (cur:Incident {id: $incident_id})-[:uses_ttp]->(t:TTP)<-[:uses_ttp]-(prior:Incident)
WHERE prior.id <> cur.id
WITH prior, count(DISTINCT t) AS shared_ttps, collect(DISTINCT t.id) AS ttp_list
RETURN prior.id, prior.severity, shared_ttps, ttp_list,
       shared_ttps * savitar.impact(prior) AS relevance
ORDER BY relevance DESC LIMIT 25;
```

## 5. Shared service accounts across exposed assets

```cypher
MATCH (sa:Identity {kind: 'service_account'})-[:runs_on]->(a:Asset {exposed: true})
WITH sa, count(DISTINCT a) AS exposed_count,
     collect(DISTINCT a.id) AS assets,
     collect(DISTINCT a.business_unit) AS bus
WHERE exposed_count >= 2
RETURN sa.id, sa.mfa, exposed_count, assets, bus,
       CASE WHEN sa.mfa THEN 0.85 ELSE 1.0 END * sa.privilege_score AS risk
ORDER BY risk DESC LIMIT 50;
```
