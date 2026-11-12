import { closeDb, migrate } from "./db.js";

await migrate();
await closeDb();
console.log("control-plane migrations applied");
