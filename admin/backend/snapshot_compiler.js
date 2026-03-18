const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

async function readJsonFile(filePath) {
  const raw = await fs.readFile(filePath, 'utf8');
  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new Error(`Invalid JSON in ${filePath}: ${error.message}`);
  }
}

function isPlainObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

exports.compile = async function compile(redisClient, configDir) {
  if (!redisClient) {
    throw new Error('redisClient is required');
  }

  const dir = String(configDir || '').trim();
  if (!dir) {
    throw new Error('configDir is required');
  }

  const defaultConfigPath = path.join(dir, 'default_config.json');
  const globalConfig = await readJsonFile(defaultConfigPath);
  if (!isPlainObject(globalConfig)) {
    throw new Error(`default_config.json must be an object: ${defaultConfigPath}`);
  }

  const sitesDir = path.join(dir, 'sites');
  let filenames = [];
  try {
    filenames = await fs.readdir(sitesDir);
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      filenames = [];
    } else {
      throw error;
    }
  }

  const siteFiles = filenames.filter((name) => String(name).toLowerCase().endsWith('.json'));
  const sites = {};

  for (const filename of siteFiles) {
    const filePath = path.join(sitesDir, filename);
    const siteConfig = await readJsonFile(filePath);
    if (!isPlainObject(siteConfig)) {
      throw new Error(`site config must be an object: ${filePath}`);
    }

    const domainFromConfig = typeof siteConfig.domain === 'string' ? siteConfig.domain.trim() : '';
    const domainFromFilename = path.basename(filename, '.json');
    const domain = (domainFromConfig || domainFromFilename).toLowerCase();

    if (!domain) {
      throw new Error(`site config missing domain and filename is empty: ${filePath}`);
    }

    sites[domain] = siteConfig;
  }

  const bundle = {
    version: crypto.randomUUID(),
    compiled_at: new Date().toISOString(),
    global: globalConfig,
    sites
  };

  const key = `sl:snapshot:bundle:${bundle.version}`;
  await redisClient.set(key, JSON.stringify(bundle), 'EX', 7 * 24 * 60 * 60);

  return bundle;
};

