#!/usr/bin/env -S node --loader tsx
import path from 'node:path';
import { openDb } from './lib/db.js';
const dbPath = process.argv[2] ?? 'attack.db';
const db = openDb(dbPath);
db.close();
console.error(`attack db ready: ${path.resolve(dbPath)}`);
