"use strict";

export function filterItems(items, activeFilter, resultMode) {
  if (activeFilter === "all") {
    return items;
  }
  return items.filter((item) =>
    resultMode === "diff"
      ? item.kind === activeFilter
      : item.finding?.severity === activeFilter,
  );
}

function yamlScalar(value) {
  return JSON.stringify(String(value));
}

export function githubAction(mode, request) {
  const lines = [
    "name: Preview security",
    "",
    "on:",
    "  pull_request:",
    "",
    "permissions:",
    "  contents: read",
    "",
    "jobs:",
    "  previewshield:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v6",
    "      - name: Check web security",
    "        uses: devUmut35/PreviewShield@v1",
    "        with:",
  ];
  if (mode === "diff") {
    lines.push(`          baseline: ${yamlScalar(request.baseline)}`);
    lines.push("          preview: ${{ vars.PREVIEW_URL }}");
  } else {
    lines.push(`          target: ${yamlScalar(request.target)}`);
  }
  lines.push(`          fail-on: ${yamlScalar(request.fail_on)}`);
  lines.push("          paths: |");
  request.paths.forEach((route) => lines.push(`            ${String(route)}`));
  return `${lines.join("\n")}\n`;
}
