// fetch-scid.js
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

(async () => {
	const browser = await chromium.launch();
	const page = await browser.newPage();

	// CSV-Download abfangen
	const [download] = await Promise.all([
		page.waitForEvent('download'),
		(async () => {
			await page.goto('https://docs.kaidojarvemets.com/defender-scid-explorer.html');
			// Warten bis Daten geladen
			await page.waitForSelector('text=Export as CSV', { timeout: 10000 });
			await page.click('text=Export as CSV');
		})()
	]);

	const csvPath = path.join('data', 'scid.csv');
	fs.mkdirSync('data', { recursive: true });
	await download.saveAs(csvPath);

	console.log('CSV saved to', csvPath);
	await browser.close();
})();
