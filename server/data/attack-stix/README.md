# ATT&CK STIX Data Mirror

This directory contains a vendored subset of the MITRE ATT&CK Enterprise dataset (v15).

## Source
MITRE ATT&CK Enterprise v15: https://github.com/mitre/cti/tree/master/enterprise-attack

## Format
`techniques.json` — array of technique records extracted from the STIX bundle.
Each record contains: id, name, tactic(s), description, platforms, data_sources,
is_subtechnique, parent_id (for sub-techniques), is_revoked, kill_chain_phases.

## Update Process
Run: `npx tsx server/scripts/sync-attack-stix.ts`
This fetches the latest bundle from the MITRE CTI repo and rebuilds techniques.json.

## Usage
Import via `server/services/aev/attack-engine.ts` — data is loaded once at startup
and cached in memory. No runtime network requests.
