const crypto = require("node:crypto");
const process = require('node:process');
const child_process = require('node:child_process');

const puppeteer = require("puppeteer");

const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false,
});
readline.ask = str => new Promise(resolve => readline.question(str, resolve));

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

const FLAG = process.env.FLAG || 'flag{example_flag}';
const TIMEOUT = process.env.TIMEOUT || 300 * 1000;
const EXCESS_URL = process.env.EXCESS_URL || 'http://localhost:31337/';

const POW_BITS = process.env.POW_BITS || 28;

async function pow() {
    const nonce = crypto.randomBytes(8).toString('hex');

    console.log('[*] Please solve PoW:');
    console.log(`hashcash -q -mb${POW_BITS} ${nonce}`);

    const answer = await readline.ask('> ');

    const check = child_process.spawnSync(
        '/usr/bin/hashcash',
        ['-q', '-f', '/tmp/bot/hashcash.sdb', `-cdb${POW_BITS}`, '-r', nonce, answer],
    );
    const correct = (check.status === 0);

    if (!correct) {
        console.log('[-] Incorrect.');
        process.exit(0);
    }

    console.log('[+] Correct.');
}

async function visit(url) {
    const params = {
        browser: 'chrome',
        args: [
            '--no-sandbox',
            '--disable-gpu',
            '--disable-extensions',
            '--js-flags=--jitless',
        ],
        headless: true,
    };

    const browser = await puppeteer.launch(params);
    const context = await browser.createBrowserContext();

    const pid = browser.process().pid;

    const shutdown = async () => {
        await context.close();
        await browser.close();

        try {
            process.kill(pid, 'SIGKILL');
        } catch(_) { }

        process.exit(0);
    };

    const name = crypto.randomBytes(8).toString('hex');
    const password = crypto.randomBytes(8).toString('hex');

    const page1 = await context.newPage();
    await page1.goto(EXCESS_URL);

    await page1.waitForNavigation();

    await page1.waitForSelector('input[name="name"]');
    await page1.type('input[name="name"]', name);
    await page1.waitForSelector('input[name="password"]');
    await page1.type('input[name="password"]', password);
    await page1.waitForSelector('#register');
    await page1.click('#register');

    await page1.waitForSelector('#add');
    await page1.click('#add');

    await page1.waitForSelector('input[name="title"]');
    await page1.type('input[name="title"]', 'flag');
    await page1.waitForSelector('input[name="content"]');
    await page1.type('input[name="content"]', FLAG);
    await page1.waitForSelector('#add');
    await page1.click('#add');

    await page1.waitForSelector('#back');
    await page1.close();

    setTimeout(() => shutdown(), TIMEOUT);
    
    const page2 = await context.newPage();
    await page2.goto(url);
}

async function main() {
    if (POW_BITS > 0) {
        await pow();
    }

    console.log('[?] Please input URL:');
    const url = await readline.ask('> ');

    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        console.log('[-] Invalid scheme.');
        process.exit(0);
    }

    console.log('[+] OK.');

    readline.close()
    process.stdin.end();
    process.stdout.end();

    await visit(url);

    await sleep(TIMEOUT);
}

main();
