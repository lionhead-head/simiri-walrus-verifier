#!/usr/bin/env node
import { open } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { formatReport, INPUT_LIMIT, verifyRecord } from "./verifier-core.mjs";

const USAGE =
  "Usage: node verify.mjs <public-receipt.json> [--max-age-hours <hours>]\nExit: 0 PASS, 1 FAIL, 2 invalid usage/input file. Default maximum age24h.\n";
export async function main(argv, io = { stdout: process.stdout, stderr: process.stderr }) {
  if (argv.length === 1 && argv[0] === "--help") {
    io.stdout.write(USAGE);
    return 0;
  }
  let maxAgeHours = 24;
  if ((argv.length !== 1 && argv.length !== 3) || !argv[0] || argv[0].startsWith("--")) {
    io.stderr.write(USAGE);
    return 2;
  }
  if (argv.length === 3) {
    maxAgeHours = Number(argv[2]);
    if (
      argv[1] !== "--max-age-hours" ||
      !Number.isFinite(maxAgeHours) ||
      maxAgeHours <= 0 ||
      maxAgeHours > 8760
    ) {
      io.stderr.write(USAGE);
      return 2;
    }
  }
  let handle;
  let input;
  try {
    handle = await open(argv[0], "r");
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > INPUT_LIMIT) throw new Error();
    const chunks = [];
    let size = 0;
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      size += chunk.length;
      if (size > INPUT_LIMIT) throw new Error();
      chunks.push(chunk);
    }
    input = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, size)),
    );
  } catch {
    io.stderr.write("FAIL INPUT_FILE_INVALID\n");
    return 2;
  } finally {
    await handle?.close();
  }
  const result = await verifyRecord(input, { maxAgeHours });
  io.stdout.write(formatReport(result));
  return result.ok ? 0 : 1;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    () => {
      process.stderr.write("FAIL VERIFIER_FAILED\n");
      process.exitCode = 1;
    },
  );
}
