import { Firestore } from "@google-cloud/firestore";
import * as fs from "fs";
import * as path from "path";

const configPath = path.join(process.cwd(), "firebase-applet-config.json");
if (!fs.existsSync(configPath)) {
  console.error("Config file not found!");
  process.exit(1);
}

const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));

console.log("Using projectId:", config.projectId);
console.log("Using databaseId:", config.firestoreDatabaseId);

const firestore = new Firestore();

async function test() {
  try {
    console.log("Fetching reports with @google-cloud/firestore admin SDK...");
    const collections = await firestore.listCollections();
    console.log("Success! Collections found:", collections.map(c => c.id));
    
    console.log("Fetching documents from 'reports' collection...");
    const querySnapshot = await firestore.collection("reports").get();
    console.log(`Success! Found ${querySnapshot.size} reports.`);
    
    process.exit(0);
  } catch (err: any) {
    console.error("Admin SDK test failed with error:", err);
    process.exit(1);
  }
}

test();
