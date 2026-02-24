import { createClient } from 'redis';

/**
 * Redis client configuration
 * Used for distributed session storage and caching
 */

const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';

export const redisClient = createClient({
  url: redisUrl,
  socket: {
    reconnectStrategy: (retries) => {
      if (retries > 10) {
        console.error('Redis connection failed after 10 retries');
        return new Error('Redis connection failed');
      }
      // Exponential backoff: 50ms, 100ms, 200ms, 400ms, etc.
      return Math.min(retries * 50, 3000);
    },
  },
});

// Error handling
redisClient.on('error', (err) => {
  console.error('Redis Client Error:', err);
});

redisClient.on('connect', () => {
  console.log('Redis client connected');
});

redisClient.on('ready', () => {
  console.log('Redis client ready');
});

redisClient.on('reconnecting', () => {
  console.log('Redis client reconnecting');
});

// Connect to Redis (only if not in test environment)
if (process.env.NODE_ENV !== 'test') {
  redisClient.connect().catch((err) => {
    console.error('Failed to connect to Redis:', err);
  });
}

export default redisClient;
