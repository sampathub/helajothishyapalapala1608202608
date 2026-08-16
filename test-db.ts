import { initializeApp } from "firebase/app";
import { initializeFirestore, doc, setDoc, getDoc } from "firebase/firestore";
import * as fs from "fs";
import * as path from "path";

const configPath = path.join(process.cwd(), "firebase-applet-config.json");
if (!fs.existsSync(configPath)) {
  console.error("Config file not found!");
  process.exit(1);
}

const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));

async function testDatabase(dbId: string) {
  console.log(`\n--- Testing Database ID: ${dbId} ---`);
  const firebaseApp = initializeApp({
    apiKey: config.apiKey,
    authDomain: config.authDomain,
    projectId: config.projectId,
    storageBucket: config.storageBucket,
    messagingSenderId: config.messagingSenderId,
    appId: config.appId
  }, dbId);

  const firestoreDb = initializeFirestore(firebaseApp, {
    experimentalForceLongPolling: true
  }, dbId);

  try {
    const docRef = doc(firestoreDb, "reports", "test-report-id-123");
    console.log("Writing test document...");
    await setDoc(docRef, {
      id: "test-report-id-123",
      contactValue: "test@example.com",
      createdAt: new Date().toISOString()
    });
    console.log("Success! Document written.");
    
    console.log("Reading test document...");
    const snap = await getDoc(docRef);
    if (snap.exists()) {
      console.log("Success! Read document data:", snap.data());
    } else {
      console.log("Document does not exist, but no permission error occurred!");
    }
    return true;
  } catch (err: any) {
    console.error(`Failed with error: [${err.code}] ${err.message}`);
    return false;
  }
}

async function run() {
  const customId = config.firestoreDatabaseId || "";
  const r1 = await testDatabase("(default)");
  let r2 = false;
  if (customId && customId !== "(default)") {
    r2 = await testDatabase(customId);
  }
  process.exit(r1 || r2 ? 0 : 1);
}

run();
