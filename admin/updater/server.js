const express = require('express');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);
const app = express();

const PORT = parseInt(process.env.PORT || '3400', 10);
const SHARED_SECRET = String(
  process.env.UPDATER_SHARED_SECRET
  || process.env.UPDATER_SHARED_TOKEN
  || ''
);
const DOCKER_SOCKET = process.env.UPDATER_DOCKER_SOCKET || '/var/run/docker.sock';
const WORKDIR = path.resolve(process.env.UPDATER_WORKDIR || '/workspace');
const HOST_WORKDIR_ENV = String(process.env.UPDATER_HOST_WORKDIR || '').trim();
const STATE_DIR = path.resolve(process.env.UPDATER_STATE_DIR || '/app/config/update');
const STATE_FILE = path.join(STATE_DIR, 'state.json');
const LOG_FILE = path.join(STATE_DIR, 'update.log');
const DEFAULT_COMPOSE_FILE = path.basename(process.env.UPDATER_COMPOSE_FILE || 'docker-compose.prod.yml');
const FALLBACK_COMPOSE_FILE = path.basename(process.env.UPDATER_FALLBACK_COMPOSE_FILE || 'docker-compose.yml');
const RUNNER_IMAGE = String(process.env.UPDATER_RUNNER_IMAGE || 'safeline-waf-admin-updater:local').trim();
const RUNNER_CONTAINER_PREFIX = String(process.env.UPDATER_RUNNER_CONTAINER_PREFIX || 'safeline-waf-update-runner').trim();
const PULL_SOURCE = process.env.UPDATER_PULL_SOURCE !== 'false';
const GIT_REMOTE = String(process.env.UPDATER_GIT_REMOTE || 'origin').trim();
const GIT_BRANCH = String(process.env.UPDATER_GIT_BRANCH || 'main').trim();
const IMAGE_TAG = String(process.env.SAFELINE_TAG || process.env.UPDATER_IMAGE_TAG || 'main').trim() || 'main';
const SERVICE_LIST = String(process.env.UPDATER_SERVICES || 'nginx,redis,admin-backend,admin-frontend,admin-updater')
  .split(',')
  .map((item) => item.trim())
  .filter(Boolean);
const RUNNER_STATE_DIR = String(
  process.env.UPDATER_RUNNER_STATE_DIR
  || path.posix.join(WORKDIR.replace(/\\/g, '/'), 'data/updater')
).trim();

app.use(express.json({ limit: '32kb' }));

function getRuntimeMode(composeFile) {
  return String(composeFile || '').endsWith('.prod.yml') ? 'prod' : 'source';
}

function getRunnerDockerFlags(composeFile) {
  const mode = getRuntimeMode(composeFile);
  const pullImages = process.env.UPDATER_DOCKER_PULL !== undefined
    ? process.env.UPDATER_DOCKER_PULL !== 'false'
    : mode === 'prod';
  const buildServices = process.env.UPDATER_DOCKER_BUILD !== undefined
    ? process.env.UPDATER_DOCKER_BUILD === 'true'
    : mode === 'source';

  return { mode, pullImages, buildServices };
}

function buildExpectedContainers(services = SERVICE_LIST) {
  return services.map((service) => `safeline-waf-${service}`);
}

function timingSafeEqualString(left, right) {
  const leftBuffer = Buffer.from(String(left || ''), 'utf8');
  const rightBuffer = Buffer.from(String(right || ''), 'utf8');

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function hasUpdaterSecret() {
  return Boolean(SHARED_SECRET);
}

function authMiddleware(req, res, next) {
  if (!hasUpdaterSecret()) {
    return res.status(503).json({
      success: false,
      message: 'Updater secret is not configured',
      data: null
    });
  }

  const bearer = req.headers.authorization && req.headers.authorization.startsWith('Bearer ')
    ? req.headers.authorization.slice(7)
    : '';
  const headerSecret = req.headers['x-updater-secret'];
  const legacyHeaderSecret = req.headers['x-updater-token'];
  const provided = String(headerSecret || legacyHeaderSecret || bearer || '');

  if (!provided || !timingSafeEqualString(provided, SHARED_SECRET)) {
    return res.status(401).json({
      success: false,
      message: 'Unauthorized',
      data: null
    });
  }

  next();
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

async function readJsonFile(filePath) {
  try {
    const raw = await fsp.readFile(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      return null;
    }

    throw error;
  }
}

async function readLogTail(filePath, maxBytes = 16384) {
  try {
    const stat = await fsp.stat(filePath);
    const start = Math.max(0, stat.size - maxBytes);
    const handle = await fsp.open(filePath, 'r');
    try {
      const length = stat.size - start;
      const buffer = Buffer.alloc(length);
      await handle.read(buffer, 0, length, start);
      return buffer.toString('utf8');
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      return '';
    }

    throw error;
  }
}

async function runCommand(command, args, options = {}) {
  const { stdout, stderr } = await execFileAsync(command, args, {
    cwd: options.cwd || WORKDIR,
    env: options.env || process.env,
    maxBuffer: options.maxBuffer || 1024 * 1024
  });

  return {
    stdout: String(stdout || '').trim(),
    stderr: String(stderr || '').trim()
  };
}

function normalizePathValue(value) {
  return String(value || '').replace(/\\/g, '/').replace(/\/+$/, '');
}

async function resolveHostWorkdir() {
  if (HOST_WORKDIR_ENV && path.isAbsolute(HOST_WORKDIR_ENV)) {
    return HOST_WORKDIR_ENV;
  }

  const containerRef = String(process.env.HOSTNAME || '').trim();
  if (!containerRef) {
    return '';
  }

  try {
    const { stdout } = await runCommand('docker', [
      'inspect',
      '--format',
      '{{json .Mounts}}',
      containerRef
    ], {
      cwd: STATE_DIR,
      maxBuffer: 512 * 1024
    });

    const mounts = JSON.parse(stdout);
    const targetPath = normalizePathValue(WORKDIR);
    const matchedMount = Array.isArray(mounts)
      ? mounts.find((mount) => normalizePathValue(mount && mount.Destination) === targetPath)
      : null;

    return matchedMount && matchedMount.Source
      ? String(matchedMount.Source).trim()
      : '';
  } catch (_error) {
    return '';
  }
}

async function resolveComposeFile() {
  const preferred = path.join(WORKDIR, DEFAULT_COMPOSE_FILE);
  if (fs.existsSync(preferred)) {
    return DEFAULT_COMPOSE_FILE;
  }

  const fallback = path.join(WORKDIR, FALLBACK_COMPOSE_FILE);
  if (fs.existsSync(fallback)) {
    return FALLBACK_COMPOSE_FILE;
  }

  return DEFAULT_COMPOSE_FILE;
}

async function inspectRunnerContainer(containerName) {
  if (!containerName) {
    return null;
  }

  try {
    const { stdout } = await runCommand('docker', [
      'inspect',
      '--format',
      '{{json .State}}',
      containerName
    ], {
      cwd: STATE_DIR
    });

    return JSON.parse(stdout);
  } catch (_error) {
    return null;
  }
}

async function readRepoInfo(hostWorkdir) {
  const info = {
    workdir: WORKDIR,
    host_workdir: hostWorkdir || null,
    is_git_repo: false,
    branch: null,
    commit: null,
    short_commit: null,
    deployed_commit: null,
    deployed_short_commit: null,
    dirty: null
  };

  try {
    await runCommand('git', ['rev-parse', '--is-inside-work-tree']);
    info.is_git_repo = true;

    const [
      branchResult,
      commitResult,
      shortCommitResult,
      dirtyResult,
      deployedCommitResult,
      deployedShortCommitResult
    ] = await Promise.all([
      runCommand('git', ['rev-parse', '--abbrev-ref', 'HEAD']),
      runCommand('git', ['rev-parse', 'HEAD']),
      runCommand('git', ['rev-parse', '--short', 'HEAD']),
      runCommand('git', ['status', '--porcelain']),
      runCommand('git', ['rev-parse', '--verify', 'refs/safeline/online-update']).catch(() => ({ stdout: '' })),
      runCommand('git', ['rev-parse', '--short', '--verify', 'refs/safeline/online-update']).catch(() => ({ stdout: '' }))
    ]);

    info.branch = branchResult.stdout || null;
    info.commit = commitResult.stdout || null;
    info.short_commit = shortCommitResult.stdout || null;
    info.deployed_commit = deployedCommitResult.stdout || null;
    info.deployed_short_commit = deployedShortCommitResult.stdout || null;
    info.dirty = Boolean(dirtyResult.stdout);
  } catch (_error) {
    return info;
  }

  return info;
}

async function buildStatus() {
  await ensureStateDir();

  const composeFile = await resolveComposeFile();
  const hostWorkdir = await resolveHostWorkdir();
  const configured = Boolean(hasUpdaterSecret() && hostWorkdir);
  const persistedState = (await readJsonFile(STATE_FILE)) || {
    status: 'idle',
    phase: 'idle',
    message: 'No update has been started yet'
  };
  const normalizedStatus = persistedState.status === 'succeeded'
    ? 'success'
    : (persistedState.status || 'idle');
  const runnerState = await inspectRunnerContainer(persistedState.runner_container);
  const repo = await readRepoInfo(hostWorkdir);
  const logTail = await readLogTail(LOG_FILE);
  const statusFromState = normalizedStatus === 'queued' ? 'running' : normalizedStatus;
  const runnerMissing = statusFromState === 'running'
    && Boolean(persistedState.runner_container)
    && !runnerState;
  const effectiveStatus = runnerMissing ? 'failed' : statusFromState;
  const running = effectiveStatus === 'running'
    && !!runnerState
    && (runnerState.Status === 'running' || runnerState.Status === 'created');
  const dockerFlags = getRunnerDockerFlags(composeFile);

  return {
    enabled: configured,
    available: configured,
    message: configured
      ? (runnerMissing
        ? 'Updater runner container disappeared before the job completed'
        : (persistedState.message || null))
      : 'Unable to determine host workspace mount or updater secret',
    status: effectiveStatus,
    phase: persistedState.phase || 'idle',
    running,
    current_job_id: persistedState.job_id || null,
    requested_at: persistedState.requested_at || null,
    started_at: persistedState.started_at || null,
    finished_at: persistedState.finished_at || null,
    last_started_at: persistedState.started_at || persistedState.requested_at || null,
    last_finished_at: persistedState.finished_at || null,
    requested_by: persistedState.requested_by || null,
    compose_file: composeFile,
    pull_source: PULL_SOURCE,
    git_remote: GIT_REMOTE,
    git_branch: GIT_BRANCH,
    runner_container: persistedState.runner_container || null,
    runner_status: runnerState ? runnerState.Status || null : null,
    error: runnerMissing
      ? (persistedState.error || 'Runner container missing')
      : (persistedState.error || null),
    repo,
    runtime: {
      mode: dockerFlags.mode,
      image_tag: IMAGE_TAG,
      compose_file: composeFile,
      services: SERVICE_LIST,
      docker_pull: dockerFlags.pullImages,
      docker_build: dockerFlags.buildServices,
      git: {
        branch: repo.branch || null,
        commit: repo.commit || null,
        commit_short: repo.short_commit || null,
        deployed_commit: repo.deployed_commit || null,
        deployed_commit_short: repo.deployed_short_commit || null,
        dirty: Boolean(repo.dirty)
      }
    },
    log_tail: logTail
  };
}

async function launchRunner(jobId, requestedBy, composeFile, hostWorkdir) {
  const containerName = `${RUNNER_CONTAINER_PREFIX}-${jobId}`.toLowerCase();
  const dockerFlags = getRunnerDockerFlags(composeFile);
  const expectedContainers = buildExpectedContainers(SERVICE_LIST);
  const initialState = {
    job_id: jobId,
    status: 'running',
    phase: 'queued',
    message: 'Update has been queued',
    requested_at: new Date().toISOString(),
    requested_by: requestedBy || 'admin',
    compose_file: composeFile,
    runner_container: containerName,
    runner_image: RUNNER_IMAGE,
    pull_source: PULL_SOURCE,
    pull_images: dockerFlags.pullImages,
    build_services: dockerFlags.buildServices,
    git_remote: GIT_REMOTE,
    git_branch: GIT_BRANCH,
    error: null
  };

  await writeJsonAtomic(STATE_FILE, initialState);

  const args = [
    'run',
    '-d',
    '--rm',
    '--name',
    containerName,
    '--label',
    'safeline.update.runner=true',
    '-v',
    `${DOCKER_SOCKET}:${DOCKER_SOCKET}`,
    '-v',
    `${hostWorkdir}:${WORKDIR}`,
    '-w',
    WORKDIR,
    '-e',
    `RUNNER_JOB_ID=${jobId}`,
    '-e',
    `RUNNER_REQUESTED_BY=${requestedBy || 'admin'}`,
    '-e',
    `RUNNER_WORKDIR=${WORKDIR}`,
    '-e',
    `RUNNER_STATE_DIR=${RUNNER_STATE_DIR}`,
    '-e',
    `RUNNER_COMPOSE_FILE=${composeFile}`,
    '-e',
    `RUNNER_PULL_SOURCE=${PULL_SOURCE ? 'true' : 'false'}`,
    '-e',
    `RUNNER_DOCKER_PULL=${dockerFlags.pullImages ? 'true' : 'false'}`,
    '-e',
    `RUNNER_DOCKER_BUILD=${dockerFlags.buildServices ? 'true' : 'false'}`,
    '-e',
    `RUNNER_GIT_REMOTE=${GIT_REMOTE}`,
    '-e',
    `RUNNER_GIT_BRANCH=${GIT_BRANCH}`,
    '-e',
    `RUNNER_SERVICES=${SERVICE_LIST.join(',')}`,
    '-e',
    `RUNNER_EXPECTED_CONTAINERS=${expectedContainers.join(',')}`,
    RUNNER_IMAGE,
    'node',
    '/app/runner.js'
  ];

  await runCommand('docker', args, {
    cwd: STATE_DIR,
    maxBuffer: 256 * 1024
  });

  return initialState;
}

app.get('/health', (_req, res) => {
  res.json({
    success: true,
    data: {
      status: 'ok',
      configured: hasUpdaterSecret(),
      timestamp: Date.now()
    }
  });
});

app.use(authMiddleware);

app.get('/status', async (_req, res) => {
  try {
    const data = await buildStatus();
    return res.json({ success: true, data });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || 'Failed to fetch updater status',
      data: null
    });
  }
});

app.post('/run', async (req, res) => {
  try {
    const hostWorkdir = await resolveHostWorkdir();
    if (!hasUpdaterSecret() || !hostWorkdir) {
      return res.status(503).json({
        success: false,
        message: 'Updater is not configured. Unable to resolve host workspace mount or shared secret.',
        data: null
      });
    }

    const currentStatus = await buildStatus();
    if (currentStatus.status === 'running' && currentStatus.running) {
      return res.status(409).json({
        success: false,
        message: 'An update is already running',
        data: currentStatus
      });
    }

    if (PULL_SOURCE && currentStatus.repo && currentStatus.repo.dirty) {
      return res.status(409).json({
        success: false,
        message: 'Refusing to run source-mode update with a dirty worktree',
        data: currentStatus
      });
    }

    const composeFile = await resolveComposeFile();
    const requestedBy = String((req.body && req.body.requested_by) || 'admin').slice(0, 128);
    const jobId = `${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const data = await launchRunner(jobId, requestedBy, composeFile, hostWorkdir);

    return res.json({
      success: true,
      message: 'Update started',
      data
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || 'Failed to start update',
      data: null
    });
  }
});

app.listen(PORT, async () => {
  await ensureStateDir();
  console.log(`[updater] listening on ${PORT}`);
});
