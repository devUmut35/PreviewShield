import assert from "node:assert/strict";
import test from "node:test";

import {
  filterItems,
  githubAction,
} from "../src/previewshield/webui/assets/logic.mjs";

test("result filtering uses the completed result mode", () => {
  const items = [
    { kind: "regression", finding: { severity: "high" } },
    { kind: "resolved", finding: { severity: "medium" } },
  ];

  assert.deepEqual(filterItems(items, "regression", "diff"), [items[0]]);
  assert.deepEqual(filterItems(items, "high", "scan"), [items[0]]);
});

test("GitHub Action generation uses its request mode snapshot", () => {
  const diff = githubAction("diff", {
    baseline: "https://production.example",
    preview: "https://preview.example",
    fail_on: "high",
    paths: ["/", "/login"],
  });
  const scan = githubAction("scan", {
    target: "https://single.example",
    fail_on: "medium",
    paths: ["/"],
  });

  assert.match(diff, /baseline: "https:\/\/production\.example"/u);
  assert.doesNotMatch(diff, /target:|undefined/u);
  assert.match(diff, /paths: \|\n            \/\n            \/login\n$/u);
  assert.match(scan, /target: "https:\/\/single\.example"/u);
  assert.doesNotMatch(scan, /baseline:|undefined/u);
  assert.match(scan, /paths: \|\n            \/\n$/u);
});
