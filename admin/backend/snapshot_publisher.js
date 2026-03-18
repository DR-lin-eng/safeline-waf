function normalizeVersion(value) {
  return String(value || '').trim();
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
  await redisClient
    .multi()
    .set('sl:snapshot:active', normalized)
    .set('sl:snapshot:published_at', publishedAt)
    .exec();

  return { active_version: normalized, published_at: publishedAt };
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

