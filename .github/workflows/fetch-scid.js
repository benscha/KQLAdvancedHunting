const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

(async () => {
	const browser = await chromium.launch();
	const page = await browser.newPage();

	const [download] = await Promise.all([
		page.waitForEvent('download'),
		(async () => {
			await page.goto('https://docs.kaidojarvemets.com/defender-scid-explorer.html');
			await page.waitForSelector('text=Export as CSV', { timeout: 15000 });
			await page.click('text=Export as CSV');
		})()
	]);

	const csvPath = path.join('MISC', 'scid.csv');
	fs.mkdirSync('MISC', { recursive: true });

	// Temporär speichern
	const tmpPath = path.join('MISC', 'scid_tmp.csv');
	await download.saveAs(tmpPath);

	// Kommentar-Header voranstellen
	const originalContent = fs.readFileSync(tmpPath, 'utf8');
	const header = [
		'# Thx to Kaido Järvemets for the Defender Scid Explorer',
		'# SRC: https://docs.kaidojarvemets.com/defender-scid-explorer',
		''
	].join('\n');
	fs.writeFileSync(csvPath, header + originalContent, 'utf8');
	fs.unlinkSync(tmpPath);

	console.log('CSV saved to', csvPath);
	await browser.close();
})();
