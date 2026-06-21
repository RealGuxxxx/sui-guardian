module.exports = {
  apps: [
    {
      name: 'sui-guardian-daemon',
      script: 'dist/index.js',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '1G',
      env: {
        NODE_ENV: 'production',
        PORT: '3123',
        HOST: '0.0.0.0',
        CONFIG_PATH: 'config/default.yml'
      }
    }
  ]
};
