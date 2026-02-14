#!/usr/bin/env node
'use strict';

const { runCLI } = require('../dist/cli/index.js');

runCLI(process.argv.slice(2)).catch((err) => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
