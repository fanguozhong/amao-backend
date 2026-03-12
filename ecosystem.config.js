{
  "apps": [{
    "name": "amao-backend",
    "script": "src/index.js",
    "instances": "max",
    "exec_mode": "cluster",
    "watch": false,
    "max_memory_restart": "500M",
    "env": {
      "NODE_ENV": "development",
      "PORT": 3000
    },
    "env_production": {
      "NODE_ENV": "production",
      "PORT": 3000
    },
    "error_file": "./logs/error.log",
    "out_file": "./logs/out.log",
    "log_date_format": "YYYY-MM-DD HH:mm:ss",
    "merge_logs": true,
    "autorestart": true,
    "max_restarts": 10,
    "min_uptime": "10s",
    "graceful_shutdown_timeout": 10000
  }]
}
