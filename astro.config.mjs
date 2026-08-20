// @ts-check
import { defineConfig } from 'astro/config';
import node from '@astrojs/node';

// Astro config for the auth template.
// - SSR via the Node adapter (standalone mode => `node ./dist/server/entry.mjs`).
// - No Astro session driver: this template manages its own cookie sessions
//   backed by LibSQL (see src/lib/session.js).
export default defineConfig({
  output: 'server',
  adapter: node({
    mode: 'standalone',
  }),
  session: false,
});
