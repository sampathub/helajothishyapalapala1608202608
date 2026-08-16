console.log("Environment Keys:", Object.keys(process.env).filter(k => !k.includes("KEY") && !k.includes("SECRET") && !k.includes("PASSWORD")));
console.log("Full Env:", JSON.stringify(Object.keys(process.env)));

