import * as fs from "fs";
import * as path from "path";

async function getAccessToken(): Promise<string | null> {
  try {
    const res = await fetch("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", {
      headers: { "Metadata-Flavor": "Google" }
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch metadata token: ${res.statusText}`);
    }
    const data: any = await res.json();
    return data.access_token;
  } catch (err) {
    console.error("Error fetching access token from metadata server:", err);
    return null;
  }
}

async function deploy() {
  const token = await getAccessToken();
  if (!token) {
    console.error("Could not obtain access token.");
    process.exit(1);
  }

  const configPath = path.join(process.cwd(), "firebase-applet-config.json");
  const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));
  const projectId = config.projectId;
  const databaseId = config.firestoreDatabaseId;

  console.log(`Using Project ID: ${projectId}`);
  console.log(`Using Database ID: ${databaseId}`);

  const rulesContent = fs.readFileSync(path.join(process.cwd(), "firestore.rules"), "utf-8");

  try {
    // 1. Create Ruleset
    console.log("Creating Ruleset...");
    const rulesetRes = await fetch(`https://firebaserules.googleapis.com/v1/projects/${projectId}/rulesets`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        source: {
          files: [
            {
              name: "firestore.rules",
              content: rulesContent
            }
          ]
        }
      })
    });

    const rulesetData: any = await rulesetRes.json();
    if (!rulesetRes.ok) {
      throw new Error(`Create Ruleset failed: ${JSON.stringify(rulesetData)}`);
    }

    const rulesetName = rulesetData.name;
    console.log(`Ruleset created successfully: ${rulesetName}`);

    // 2. Release Ruleset to custom database
    const releaseName = `projects/${projectId}/releases/cloud.firestore%2Fdatabases%2F${databaseId}`;
    console.log(`Releasing Ruleset to: cloud.firestore/databases/${databaseId}...`);
    
    const releaseRes = await fetch(`https://firebaserules.googleapis.com/v1/${releaseName}`, {
      method: "PATCH",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        release: {
          name: releaseName,
          rulesetName: rulesetName
        }
      })
    });

    const releaseData: any = await releaseRes.json();
    if (!releaseRes.ok) {
      throw new Error(`Release failed: ${JSON.stringify(releaseData)}`);
    }

    console.log("Rules released successfully!");
    process.exit(0);
  } catch (err: any) {
    console.error("Deployment failed:", err.message || err);
    process.exit(1);
  }
}

deploy();
