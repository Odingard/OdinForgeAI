/**
 * sync-attack-stix.ts
 *
 * Fetches the MITRE ATT&CK Enterprise STIX bundle from the official CTI repo
 * and extracts a compact techniques.json suitable for runtime use.
 *
 * Run: npx tsx server/scripts/sync-attack-stix.ts
 */

import { writeFileSync } from "fs";
import { join } from "path";

const STIX_URL =
  "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";

const OUTPUT = join(__dirname, "../data/attack-stix/techniques.json");

interface StixObject {
  type: string;
  id: string;
  name: string;
  description?: string;
  kill_chain_phases?: Array<{ kill_chain_name: string; phase_name: string }>;
  external_references?: Array<{ source_name: string; external_id?: string; url?: string }>;
  x_mitre_is_subtechnique?: boolean;
  x_mitre_platforms?: string[];
  x_mitre_data_sources?: string[];
  x_mitre_deprecated?: boolean;
  revoked?: boolean;
}

interface AttackTechnique {
  id: string;           // e.g. "T1059"
  subId?: string;       // e.g. ".001" for sub-techniques
  fullId: string;       // e.g. "T1059.001"
  name: string;
  tactics: string[];    // kill_chain phase names
  description: string;
  platforms: string[];
  dataSources: string[];
  isSubTechnique: boolean;
  parentId?: string;
  url: string;
}

async function main() {
  console.log("Fetching ATT&CK STIX bundle...");
  const res = await fetch(STIX_URL);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);

  const bundle = (await res.json()) as { objects: StixObject[] };
  const techniques: AttackTechnique[] = [];

  for (const obj of bundle.objects) {
    if (obj.type !== "attack-pattern") continue;
    if (obj.revoked || obj.x_mitre_deprecated) continue;

    const extRef = obj.external_references?.find(r => r.source_name === "mitre-attack");
    const fullId = extRef?.external_id || "";
    if (!fullId.startsWith("T")) continue;

    const isSubTechnique = obj.x_mitre_is_subtechnique ?? false;
    const [baseId, subSuffix] = fullId.split(".");

    const tactics = (obj.kill_chain_phases || [])
      .filter(p => p.kill_chain_name === "mitre-attack")
      .map(p => p.phase_name);

    techniques.push({
      id: baseId,
      subId: subSuffix ? `.${subSuffix}` : undefined,
      fullId,
      name: obj.name,
      tactics,
      description: (obj.description || "").slice(0, 400),
      platforms: obj.x_mitre_platforms || [],
      dataSources: obj.x_mitre_data_sources || [],
      isSubTechnique,
      parentId: isSubTechnique ? baseId : undefined,
      url: extRef?.url || `https://attack.mitre.org/techniques/${fullId.replace(".", "/")}/`,
    });
  }

  writeFileSync(OUTPUT, JSON.stringify(techniques, null, 2), "utf-8");
  console.log(`Wrote ${techniques.length} techniques to ${OUTPUT}`);
}

main().catch((err) => { console.error(err); process.exit(1); });
