// Verify Yarn Classic loads the library's config during Git preparation.
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-common-git-install-'));
const dependency = path.join(root, 'dependency');
const consumer = path.join(root, 'consumer');
const env = { ...process.env };
// Test repository configuration without environment overrides masking it.
delete env.YARN_CACHE_FOLDER;
delete env.YARN_NETWORK_CONCURRENCY;
const run = (command, args, cwd) => execFileSync(command, args, {
	cwd, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
});

try {
	fs.mkdirSync(dependency);
	fs.mkdirSync(consumer);
	fs.copyFileSync(path.join(__dirname, '../.yarnrc'), path.join(dependency, '.yarnrc'));
	fs.writeFileSync(path.join(dependency, 'package.json'), JSON.stringify({
		name: 'git-prepare-fixture', version: '1.0.0', license: 'MIT',
		files: ['dist'], scripts: { prepare: 'node prepare.cjs' },
	}));
	fs.writeFileSync(path.join(dependency, 'prepare.cjs'), `
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const cache = execFileSync('yarn', ['cache', 'dir'], { encoding: 'utf8' }).trim();
assert.equal(cache, path.join(__dirname, '.yarn-cache', 'v6'));
const concurrency = execFileSync('yarn', ['config', 'get', 'network-concurrency'], { encoding: 'utf8' }).trim();
assert.equal(concurrency, '1');
fs.mkdirSync('dist');
fs.writeFileSync('dist/prepared.json', JSON.stringify({ cache, concurrency }));
`);
	run('git', ['init', '--quiet'], dependency);
	run('git', ['add', '.'], dependency);
	run('git', ['-c', 'user.name=Install Test', '-c', 'user.email=test@example.invalid',
		'-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Fixture'], dependency);
	fs.writeFileSync(path.join(consumer, 'package.json'), JSON.stringify({
		name: 'consumer-fixture', version: '1.0.0', license: 'MIT',
		dependencies: { 'git-prepare-fixture': `git+file://${dependency}` },
	}));
	const consumerCache = path.join(root, 'consumer-cache');
	run('yarn', ['install', '--production', '--offline', '--non-interactive',
		'--cache-folder', consumerCache], consumer);
	const prepared = JSON.parse(fs.readFileSync(path.join(consumer,
		'node_modules/git-prepare-fixture/dist/prepared.json'), 'utf8'));
	assert.equal(prepared.concurrency, '1');
	assert.ok(prepared.cache.includes('.prepare/.yarn-cache/v6'));
	assert.notEqual(prepared.cache, path.join(consumerCache, 'v6'));
	console.log('PASS: production Git preparation uses an isolated cache and concurrency 1');
} finally {
	fs.rmSync(root, { recursive: true, force: true });
}
