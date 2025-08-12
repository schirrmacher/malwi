// JavaScript Import Patterns Test Suite
// Tests various import/export patterns in modern JavaScript

// ES6 Default imports
import React from 'react';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import os from 'os';
import child_process from 'child_process';

// Named imports
import { readFile, writeFile, existsSync } from 'fs';
import { join, resolve, dirname, basename } from 'path';
import { createHash, randomBytes, pbkdf2Sync } from 'crypto';
import { platform, arch, tmpdir, homedir } from 'os';
import { exec, spawn, fork } from 'child_process';

// Mixed imports (default + named)
import express, { Router, static as staticFiles } from 'express';
import axios, { get, post, put, delete as del } from 'axios';

// Aliased imports
import { readFile as read, writeFile as write } from 'fs';
import { join as pathJoin, resolve as pathResolve } from 'path';
import { createHash as hash, randomBytes as random } from 'crypto';

// Wildcard imports (namespace imports)
import * as fsModule from 'fs';
import * as pathModule from 'path';
import * as cryptoModule from 'crypto';
import * as osModule from 'os';

// Side-effect imports (imports without bindings)
import 'core-js/stable';
import './malicious-polyfill.js';
import '../../../config/secret-keys.json';

// Potentially suspicious module patterns (common in malware)
import keytar from 'keytar';
import node_pty from 'node-pty';
import screenshot_desktop from 'screenshot-desktop';
import robotjs from 'robotjs';
import mic from 'mic';
import systeminformation from 'systeminformation';

// Export statements
export const exportedConst = 'test-export';
export function exportedFunction() { return 'exported'; }
export default { defaultExport: true };

// CommonJS require() patterns
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const childProcess = require('child_process');

// Destructured require
const { readFile, writeFile, existsSync } = require('fs');
const { join, resolve, dirname } = require('path');
const { createHash, randomBytes } = require('crypto');
const { exec, spawn } = require('child_process');

// Aliased require
const cp = require('child_process');
const fsPromises = require('fs').promises;
const pathUtils = require('path');

// Conditional require (evasion pattern)
let platform_module;
try {
    platform_module = require('os');
    const platform = platform_module.platform();
} catch (e) {
    // Fallback or evasion
}

// Dynamic require (obfuscation pattern)
const moduleName = 'fs';
const dynamicModule = require(moduleName);
const encodedModule = require(Buffer.from('ZnM=', 'base64').toString());

console.log("Import patterns test completed");