import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/browser',
  workers: 1,
  use: { baseURL: 'http://127.0.0.1:8898', httpCredentials: { username: 'admin', password: 'x'.repeat(32) } },
  webServer: {
    command: `${process.env.BASTION_PYTHON || 'python3'} tests/browser_server.py`,
    url: 'http://127.0.0.1:8898/__dashboard',
    reuseExistingServer: false,
    timeout: 30000
  }
});
