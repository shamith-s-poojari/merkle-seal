// Runs the shared cases under Node's built-in test runner: `npm test`.
import { test } from 'node:test';
import { cases } from './cases.js';

for (const { name, fn } of cases) test(name, fn);
