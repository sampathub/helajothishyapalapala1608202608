import { Firestore } from "@google-cloud/firestore";
import * as fs from "fs";
import * as path from "path";

const configPath = path.join(process.cwd(), "firebase-applet-config.json");
if (!fs.existsSync(configPath)) {
  console.error("Config file not found!");
  process.exit(1);
}

const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));
const databaseId = config.firestoreDatabaseId || "(default)";
const projectId = config.projectId;

console.log(`Testing @google-cloud/firestore Admin SDK on database: ${databaseId}, project: ${projectId}`);

const firestoreDb = new Firestore({
  projectId: projectId,
  databaseId: databaseId
});

async function run() {
  try {
    const docRef = firestoreDb.collection("reports").doc("test-admin-id-123");
    console.log("Writing test document via Admin SDK...");
    await docRef.set({
      id: "test-admin-id-123",
      contactValue: "admin@example.com",
      createdAt: new Date().toISOString()
    });
    console.log("Success! Document written via Admin SDK.");
    
    console.log("Reading test document...");
    const snap = await docRef.get();
    if (snap.exists) {
      console.log("Success! Read document data:", snap.data());
    } else {
      console.log("Document does not exist!");
    }
    process.exit(0);
  } catch (err: any) {
    console.error(`Failed with error: [${err.code}] ${err.message}`);
    process.exit(1);
  }
}

run();
