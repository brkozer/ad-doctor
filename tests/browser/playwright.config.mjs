import { defineConfig } from "@playwright/test";

// The pages under test are built by `npm run fixtures` (Python) into ./build.
export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.mjs",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI ? [["list"], ["github"]] : "list",
  use: { browserName: "chromium", headless: true },
  projects: [
    { name: "desktop", use: { viewport: { width: 1440, height: 900 }, colorScheme: "light" } },
    { name: "phone", use: { viewport: { width: 390, height: 844 }, colorScheme: "dark", isMobile: true, hasTouch: true } },
  ],
});
