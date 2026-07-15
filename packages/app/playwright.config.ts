import { defineConfig } from '@playwright/test';

// Slow-mo + video so the RBAC cause/effect is watchable frame by frame.
export default defineConfig({
  testDir: './tests',
  testMatch: '**/*.spec.ts', // *.test.ts belongs to Vitest
  timeout: 240000,
  reporter: [['list']],
  use: {
    headless: true,
    launchOptions: { slowMo: 450 }, // 450ms between actions = "slomo"
    video: 'on',
    trace: 'on',
    viewport: { width: 1400, height: 900 },
  },
  outputDir: './test-results',
});
