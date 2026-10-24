import { test, expect } from '@playwright/test';

test('real API aggregates, safe rendering, and linked incident details', async ({ page }) => {
  await page.goto('/__dashboard');
  await expect(page.locator('#s-req')).toHaveText('205');
  await expect(page.locator('#s-blk')).toHaveText('205');
  await expect(page.locator('#feed > .row')).toHaveCount(200);
  await expect(page.locator('#actions')).toContainText('error');
  await expect(page.locator('#notifications')).toContainText('pending');
  await expect(page.locator('#feed')).toContainText('<img');
  expect(await page.evaluate(() => window.injected)).toBeUndefined();
  await page.getByRole('button', { name: 'Details', exact: true }).click();
  await expect(page.locator('#incident-detail')).toBeVisible();
  await expect(page.locator('#detail-body')).toContainText('Contributing requests');
  await expect(page.locator('#detail-body')).toContainText('Fixture: action failed');
  await page.getByRole('button', { name: 'Close', exact: true }).click();
});

test('container log source switching, pause, live email acceptance and resume', async ({ page }) => {
  await page.goto('/__dashboard');
  await expect(page.locator('#log-lines')).toContainText('blue <script>');
  expect(await page.evaluate(() => window.injected)).toBeUndefined();
  await page.locator('#log-source').selectOption('proxy');
  await expect(page.locator('#log-lines')).toContainText('proxy <script>');
  await expect(page.locator('#log-lines')).not.toContainText('blue <script>');
  await page.locator('#log-source').selectOption('blue');
  await expect(page.locator('#log-lines')).toContainText('blue <script>');
  await page.getByRole('button', { name: 'Pause display' }).click();
  expect((await page.request.post('/__test/advance')).ok()).toBe(true);
  await expect(page.locator('#notifications')).toContainText('accepted');
  await expect(page.locator('#log-lines')).not.toContainText('blue new output');
  await page.getByRole('button', { name: 'Resume display' }).click();
  await expect(page.locator('#log-lines')).toContainText('blue new output');
  await page.locator('#log-source').selectOption('red');
  await expect(page.locator('#log-state')).toContainText('unavailable');
  await expect(page.locator('#log-message')).toContainText('Collector has not reported');
});

test('SSE reconnects after failure and updates existing records without duplicates', async ({ page }) => {
  let streamAttempts = 0;
  await page.route('**/__api/v1/stream', async route => {
    streamAttempts++;
    if (streamAttempts === 1) await route.abort();
    else await route.continue();
  });
  await page.goto('/__dashboard');
  await expect(page.locator('#connection')).toHaveText('Live connection', { timeout: 15000 });
  expect(streamAttempts).toBeGreaterThanOrEqual(2);
  expect((await page.request.post('/__test/update-request')).ok()).toBe(true);
  await expect(page.locator('#feed')).toContainText('/updated');
  await expect(page.locator('#feed > .row')).toHaveCount(200);
  await expect(page.locator('#s-blk')).toHaveText('204');
});

test('unauthenticated API callers cannot read dashboard or log data', async ({ playwright }) => {
  const context = await playwright.request.newContext({ baseURL: 'http://127.0.0.1:8898',
    httpCredentials: { username: 'invalid', password: 'invalid' } });
  expect((await context.get('/__api/v1/overview')).status()).toBe(401);
  expect((await context.get('/__api/v1/logs/blue')).status()).toBe(401);
  expect((await context.get('/__assets/app.js')).status()).toBe(401);
  await context.dispose();
});
