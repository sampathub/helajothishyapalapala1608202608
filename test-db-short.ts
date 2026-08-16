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
const customId = config.firestoreDatabaseId || "";

console.log(`Testing document read/write on database ID: "${customId}"`);

const firebaseApp = initializeApp({
  apiKey: config.apiKey,
  authDomain: config.authDomain,
  projectId: config.projectId,
  storageBucket: config.storageBucket,
  messagingSenderId: config.messagingSenderId,
  appId: config.appId
});

const firestoreDb = initializeFirestore(firebaseApp, {
  experimentalForceLongPolling: true
}, customId);

async function run() {
  const timeoutPromise = new Promise((_, reject) => {
    setTimeout(() => reject(new Error("Timeout after 5 seconds")), 5000);
  });

  const writePromise = async () => {
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
  };

  try {
    await Promise.race([writePromise(), timeoutPromise]);
    process.exit(0);
  } catch (err: any) {
    console.error(`Failed with error: [${err.code || "unknown"}] ${err.message}`);
    process.exit(1);
  }
}

run();
