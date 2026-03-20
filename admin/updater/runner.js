const fsp = require('fs/promises');
const path = require('path');
const { spawn } = require('child_process');

const WORKDIR = path.resolve(process.env.RUNNER_WORKDIR || '/workspace');
const STATE_DIR = path.resolve(process.env.RUNNER_STATE_DIR || path.join(WORKDIR, 'data/updater'));
const STATE_FILE = path.join(STATE_DIR, 'state.json');
const LOG_FILE = path.join(STATE_DIR, 'update.log');
const COMPOSE_FILE = path.basename(process.env.RUNNER_COMPOSE_FILE || 'docker-compose.prod.yml');
const PULL_SOURCE = process.env.RUNNER_PULL_SOURCE !== 'false';
const PULL_IMAGES = process.env.RUNNER_DOCKER_PULL !== 'false';
const BUILD_SERVICES = process.env.RUNNER_DOCKER_BUILD === 'true';
const GIT_REMOTE = String(process.env.RUNNER_GIT_REMOTE || 'origin').trim();
const GIT_BRANCH = String(process.env.RUNNER_GIT_BRANCH || process.env.RUNNER_GIT_REF || 'main').trim();
const REQUESTED_BY = String(process.env.RUNNER_REQUESTED_BY || 'admin').trim();
const JOB_ID = String(process.env.RUNNER_JOB_ID || `${Date.now()}`).trim();
const SERVICES = String(process.env.RUNNER_SERVICES || 'nginx,redis,admin-backend,admin-frontend,admin-updater')
  .split(',')
  .map((item) => item.trim())
  .filter(Boolean);
const EXPECTED_CONTAINERS = String(
  process.env.RUNNER_EXPECTED_CONTAINERS
  || 'safeline-waf-nginx,safeline-waf-redis,safeline-waf-admin-backend,safeline-waf-admin-frontend,safeline-waf-admin-updater'
)
  .split(',')
  .map((item) => item.trim())
  .filter(Boolean);
const SAFE_SYNC_PATHS = ['admin', 'nginx', 'scripts', 'docker-compose.yml', 'docker-compose.prod.yml'];

let currentState = {
  job_id: JOB_ID,
  status: 'running',
  phase: 'initializing',
  requested_by: REQUESTED_BY,
  compose_file: COMPOSE_FILE,
  pull_source: PULL_SOURCE,
  pull_images: PULL_IMAGES,
  build_services: BUILD_SERVICES,
  git_remote: GIT_REMOTE,
  git_branch: GIT_BRANCH,
  started_at: new Date().toISOString(),
  message: 'Preparing online update',
  error: null
};

function chunkArray(list, size) {
  const chunks = [];
  for (let index = 0; index < list.length; index += size) {
    chunks.push(list.slice(index, index + size));
  }
  return chunks;
}

function sanitizeRelativePath(value) {
  return String(value || '')
    .replace(/\\/g, '/')
    .replace(/^\.?\//, '')
    .replace(/^\/+/, '');
}

function isSafeSyncedPath(relativePath) {
  const normalized = sanitizeRelativePath(relativePath);
  if (!normalized || normalized.startsWith('config/') || normalized.startsWith('logs/')) {
    return false;
  }

  if (normalized === 'docker-compose.yml' || normalized === 'docker-compose.prod.yml') {
    return true;
  }

  return normalized.startsWith('admin/')
    || normalized.startsWith('nginx/')
    || normalized.startsWith('scripts/');
}

async function ensureStateDir() {
  await fsp.mkdir(STATE_DIR, { recursive: true });
}

async function writeJsonAtomic(filePath, payload) {
  const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  const body = `${JSON.stringify(payload, null, 2)}\n`;
  await fsp.writeFile(tempPath, body, 'utf8');
  await fsp.rename(tempPath, filePath);
}

async function appendLog(line) {
  const prefix = new Date().toISOString();
  await fsp.appendFile(LOG_FILE, `[${prefix}] ${line}\n`, 'utf8');
}

async function updateState(patch) {
  currentState = {
    ...currentState,
    ...patch
  };

  await writeJsonAtomic(STATE_FILE, currentState);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function runCommand(command, args, options = {}) {
  await appendLog(`$ ${command} ${args.join(' ')}`);

  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd || WORKDIR,
      env: {
        ...process.env,
        ...(options.env || {})
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });

    let output = '';

    const handleChunk = (chunk, streamName) => {
      const text = String(chunk || '');
      output += text;
      text
        .split(/\r?\n/)
        .filter(Boolean)
        .forEach((line) => {
          appendLog(`${streamName}> ${line}`).catch(() => {});
        });
    };

    child.stdout.on('data', (chunk) => handleChunk(chunk, 'stdout'));
    child.stderr.on('data', (chunk) => handleChunk(chunk, 'stderr'));
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) {
        resolve(output.trim());
        return;
      }

      reject(new Error(output.trim() || `${command} exited with code ${code}`));
    });
  });
}

async function commandSucceeds(command, args, options = {}) {
  try {
    await runCommand(command, args, options);
    return true;
  } catch (_error) {
    return false;
  }
}

async function inspectContainer(name) {
  try {
    const raw = await runCommand('docker', ['inspect', name]);
    const payload = JSON.parse(raw);
    const container = Array.isArray(payload) ? payload[0] : null;
    if (!container || !container.State) {
      return {
        name,
        exists: false,
        state: 'missing',
        health: 'missing'
      };
    }

    return {
      name,
      exists: true,
      state: container.State.Status || 'unknown',
      health: container.State.Health ? container.State.Health.Status : 'none'
    };
  } catch (_error) {
    return {
      name,
      exists: false,
      state: 'missing',
      health: 'missing'
    };
  }
}

async function waitForContainers(timeoutMs = 120000) {
  const deadline = Date.now() + timeoutMs;
  let lastSnapshot = [];

  while (Date.now() < deadline) {
    lastSnapshot = [];
    let allReady = true;

    for (const name of EXPECTED_CONTAINERS) {
      const snapshot = await inspectContainer(name);
      lastSnapshot.push(snapshot);

      const healthPending = snapshot.health !== 'none' && snapshot.health !== 'healthy';
      if (!snapshot.exists || snapshot.state !== 'running' || healthPending) {
        allReady = false;
      }
    }

    if (allReady) {
      return lastSnapshot;
    }

    await sleep(3000);
  }

  throw new Error(`Timed out while waiting for services to become healthy: ${JSON.stringify(lastSnapshot)}`);
}

async function syncSourceFromRemote() {
  const insideRepo = await commandSucceeds('git', ['rev-parse', '--is-inside-work-tree']);
  if (!insideRepo) {
    await appendLog('Git repository not detected, skipping source sync');
    return {
      skipped: true,
      reason: 'not_a_git_repo'
    };
  }

  await runCommand('git', ['fetch', GIT_REMOTE, GIT_BRANCH]);

  const targetCommit = await runCommand('git', ['rev-parse', '--short', 'FETCH_HEAD']);
  const diffOutput = await runCommand('git', [
    'diff',
    '--name-status',
    'HEAD',
    'FETCH_HEAD',
    '--',
    ...SAFE_SYNC_PATHS
  ]);

  const checkoutPaths = new Set();
  const deletePaths = new Set();

  diffOutput
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .forEach((line) => {
      const parts = line.split('\t');
      const status = parts[0] || '';

      if (status.startsWith('R') || status.startsWith('C')) {
        const oldPath = sanitizeRelativePath(parts[1]);
        const nextPath = sanitizeRelativePath(parts[2]);
        if (isSafeSyncedPath(oldPath)) {
          deletePaths.add(oldPath);
        }
        if (isSafeSyncedPath(nextPath)) {
          checkoutPaths.add(nextPath);
        }
        return;
      }

      const filePath = sanitizeRelativePath(parts[1]);
      if (!isSafeSyncedPath(filePath)) {
        return;
      }

      if (status === 'D') {
        deletePaths.add(filePath);
        return;
      }

      checkoutPaths.add(filePath);
    });

  for (const chunk of chunkArray(Array.from(checkoutPaths), 50)) {
    await runCommand('git', ['checkout', 'FETCH_HEAD', '--', ...chunk]);
  }

  for (const relativePath of deletePaths) {
    const absolutePath = path.join(WORKDIR, relativePath);
    await fsp.rm(absolutePath, { force: true, recursive: false }).catch(() => {});
    await appendLog(`deleted> ${relativePath}`);
  }

  return {
    skipped: false,
    branch: GIT_BRANCH,
    commit: targetCommit || null,
    changed_files: checkoutPaths.size,
    deleted_files: deletePaths.size
  };
}

async function runUpdate() {
  await ensureStateDir();
  await fsp.writeFile(LOG_FILE, '', 'utf8');
  await appendLog(`==== job ${JOB_ID} started by ${REQUESTED_BY} ====`);
  await updateState({
    status: 'running',
    phase: 'preflight',
    started_at: new Date().toISOString(),
    message: 'Checking docker availability',
    error: null
  });

  await runCommand('docker', ['version']);

  let gitResult = null;
  if (PULL_SOURCE) {
    await updateState({
      phase: 'source_sync',
      message: `Synchronizing source from ${GIT_REMOTE}/${GIT_BRANCH}`
    });
    gitResult = await syncSourceFromRemote();
  } else {
    await appendLog('Source synchronization disabled, skipping git update');
  }

  if (PULL_IMAGES) {
    await updateState({
      phase: 'compose_pull',
      message: `Pulling latest images from ${COMPOSE_FILE}`
    });
    await runCommand('docker', ['compose', '-f', COMPOSE_FILE, 'pull', ...SERVICES]);
  } else {
    await appendLog('Image pull disabled, skipping docker compose pull');
  }

  const upArgs = ['compose', '-f', COMPOSE_FILE, 'up', '-d', '--remove-orphans'];
  if (BUILD_SERVICES) {
    upArgs.push('--build');
  }
  upArgs.push(...SERVICES);

  await updateState({
    phase: 'compose_up',
    message: `Applying stack updates from ${COMPOSE_FILE}`
  });
  await runCommand('docker', upArgs);

  await updateState({
    phase: 'health_check',
    message: 'Waiting for updated services to become healthy'
  });
  const checks = await waitForContainers();
  await runCommand('docker', ['compose', '-f', COMPOSE_FILE, 'ps']);

  await updateState({
    status: 'succeeded',
    phase: 'completed',
    finished_at: new Date().toISOString(),
    message: 'Online update completed successfully',
    error: null,
    git: gitResult,
    checks
  });
  await appendLog(`==== job ${JOB_ID} completed successfully ====`);
}

async function failUpdate(error) {
  await updateState({
    status: 'failed',
    phase: 'failed',
    finished_at: new Date().toISOString(),
    message: 'Online update failed',
    error: error.message || String(error)
  });
  await appendLog(`update failed: ${error.stack || error.message || error}`);
}

(async () => {
  try {
    await runUpdate();
    process.exit(0);
  } catch (error) {
    await failUpdate(error);
    process.exit(1);
  }
})();
