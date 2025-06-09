module.exports = {
  apps: [
    {
      name: "redirector",
      script: "index.js",
      watch: false,
      env: {
        NODE_ENV: "production"
      }
    }
  ]
};