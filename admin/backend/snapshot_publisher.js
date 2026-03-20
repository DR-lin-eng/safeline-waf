function normalizeVersion(value) {
  return String(value || '').trim();
}

async function writeStatus(redisClient, activeVersion, publishedAt) {
  const tx = redisClient.multi();

  if (activeVersion) {
    tx.set('sl:snapshot:active', activeVersion);
  } else {
    tx.del('sl:snapshot:active');
  }

  if (publishedAt) {
    tx.set('sl:snapshot:published_at', publishedAt);
  } else {
    tx.del('sl:snapshot:published_at');
  }

  await tx.exec();
}

exports.publish = async function publish(redisClient, version) {
  if (!redisClient) {
    throw new Error('redisClient is required');
  }

  const normalized = normalizeVersion(version);
  if (!normalized) {
    throw new Error('version is required');
  }

  const publishedAt = new Date().toISOString();
  await writeStatus(redisClient, normalized, publishedAt);

  return { active_version: normalized, published_at: publishedAt };
};

exports.setStatus = async function setStatus(redisClient, status) {
  if (!redisClient) {
    throw new Error('redisClient is required');
  }

  const activeVersion = normalizeVersion(status && status.active_version);
  const publishedAt = typeof (status && status.published_at) === 'string'
    ? status.published_at.trim()
    : '';

  await writeStatus(redisClient, activeVersion, publishedAt);

  return {
    active_version: activeVersion || null,
    published_at: publishedAt || null
  };
};

exports.getStatus = async function getStatus(redisClient) {
  if (!redisClient) {
    throw new Error('redisClient is required');
  }

  const [activeVersion, publishedAt] = await redisClient.mget(
    'sl:snapshot:active',
    'sl:snapshot:published_at'
  );

  return {
    active_version: activeVersion || null,
    published_at: publishedAt || null
  };
};
