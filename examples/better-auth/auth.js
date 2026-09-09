import { betterAuth } from "better-auth";
import Database from "better-sqlite3";

/* Better Auth owns users and sessions exactly as it normally would.
 *
 * The only change minidauth asks for is one extra field: the Tide identity this account is linked
 * to. Everything else about authentication stays here, which is the point of running the two side
 * by side rather than replacing one with the other. */
export const auth = betterAuth({
  database: new Database("app.db"),
  baseURL: process.env.APP_URL ?? "http://localhost:3000",
  secret: process.env.APP_SECRET ?? "dev-only-not-a-real-secret",
  emailAndPassword: { enabled: true },
  user: {
    additionalFields: {
      // The Tide identity. Not a credential, and not something this app may write on a whim:
      // it is only ever set from a sign-in minidauth verified.
      tideVuid: { type: "string", required: false, input: false },
    },
  },
});
