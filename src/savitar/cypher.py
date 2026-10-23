"""Five documented example Cypher queries."""

RELATED_TO_IOC = """
// 1. Related entities to an alert/IOC within 3 hops, scored.
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
ORDER BY final DESC, entity_id ASC
LIMIT 50;
"""

RECURRING_IN_BU = """
// 2. Recurring relationship patterns in a business unit over 30 days.
MATCH (a)-[r]->(b)
WHERE (a.business_unit = $bu OR b.business_unit = $bu)
  AND r.evidence.timestamp >= datetime() - duration({days: 30})
WITH labels(a)[0] AS srcT, type(r) AS rel, labels(b)[0] AS dstT, count(r) AS occ,
     collect(DISTINCT a.business_unit) AS bus
WHERE occ >= 2
RETURN srcT + ' -[:' + rel + ']-> ' + dstT AS motif,
       occ,
       occ / toFloat(size((:Asset {business_unit:$bu})) * size((:Identity {business_unit:$bu}))) AS precision,
       bus
ORDER BY precision DESC, occ DESC
LIMIT 20;
"""

RANK_BY_RELEVANCE = """
// 3. Rank a supplied list of entities by decision relevance.
UNWIND $entity_ids AS id
MATCH (n {id: id})
OPTIONAL MATCH (n)-[r]-(inc:Incident)
WITH n,
     savitar.confidence(0, collect(DISTINCT r.evidence)) AS confidence,
     savitar.recency(coalesce(max(r.evidence.timestamp), datetime())) AS recency,
     savitar.impact(n) AS impact
RETURN n.id AS entity_id, labels(n) AS types,
       confidence, recency, impact,
       confidence * recency * impact AS final
ORDER BY final DESC, entity_id ASC;
"""

PRIOR_INCIDENTS_SHARED_TTPS = """
// 4. Prior incidents that share TTPs with the current incident.
MATCH (cur:Incident {id: $incident_id})-[:uses_ttp]->(t:TTP)<-[:uses_ttp]-(prior:Incident)
WHERE prior.id <> cur.id
WITH prior, count(DISTINCT t) AS shared_ttps,
     collect(DISTINCT t.id) AS ttp_list
RETURN prior.id AS incident_id, prior.severity, shared_ttps, ttp_list,
       shared_ttps * savitar.impact(prior) AS relevance
ORDER BY relevance DESC, incident_id ASC
LIMIT 25;
"""

SHARED_SVC_ACROSS_EXPOSED = """
// 5. Service accounts running on multiple exposed assets.
MATCH (sa:Identity {kind: 'service_account'})-[:runs_on]->(a:Asset {exposed: true})
WITH sa, count(DISTINCT a) AS exposed_count,
     collect(DISTINCT a.id) AS assets,
     collect(DISTINCT a.business_unit) AS bus
WHERE exposed_count >= 2
RETURN sa.id AS service_account,
       sa.mfa AS mfa_enabled,
       exposed_count, assets, bus,
       CASE WHEN sa.mfa THEN 0.85 ELSE 1.0 END * sa.privilege_score AS risk
ORDER BY risk DESC, exposed_count DESC
LIMIT 50;
"""

QUERIES = {
    "related_to_ioc": RELATED_TO_IOC,
    "recurring_in_bu": RECURRING_IN_BU,
    "rank_by_relevance": RANK_BY_RELEVANCE,
    "prior_incidents_shared_ttps": PRIOR_INCIDENTS_SHARED_TTPS,
    "shared_svc_across_exposed": SHARED_SVC_ACROSS_EXPOSED,
}
