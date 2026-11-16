# Security audit: path traversal, sandbox escape, SSRF

Scope: recovered Claude Code CLI tree under `/workspace`. Focus limited to path traversal, sandbox escape, arbitrary file read/write, SSRF, and unsafe URL fetching in the listed tools/helpers.

## Summary

Two **HIGH** findings validated with complete attack chains that bypass the intended permission model. WebFetch SSRF and several path-related candidates were reviewed and discarded as near-misses (see below).

---

## Finding 1 — CLAUDE.md / `@include` symlink escapes external-include gate

| Field | Value |
| --- | --- |
| **Severity** | HIGH |
| **Location** | `src/utils/claudemd.ts` |
| **CWE** | CWE-59 (Improper Link Resolution Before File Access) |

### Evidence

- Include paths resolved with lexical `expandPath` only:

```475:487:src/utils/claudemd.ts
      // Accept @path, @./path, @~/path, or @/path
      if (path) {
        const isValidPath =
          path.startsWith('./') ||
          path.startsWith('~/') ||
          (path.startsWith('/') && path !== '/') ||
          (!path.startsWith('@') &&
            !path.match(/^[#%^&*()]+/) &&
            path.match(/^[a-zA-Z0-9._-]/))

        if (isValidPath) {
          const resolvedPath = expandPath(path, dirname(basePath))
          absolutePaths.add(resolvedPath)
```

- External gate is lexical cwd membership only:

```245:247:src/utils/claudemd.ts
function pathInOriginalCwd(path: string): boolean {
  return pathInWorkingPath(path, getOriginalCwd())
}
```

```666:670:src/utils/claudemd.ts
  for (const resolvedIncludePath of resolvedIncludePaths) {
    const isExternal = !pathInOriginalCwd(resolvedIncludePath)
    if (isExternal && !includeExternal) {
      continue
    }
```

- Read follows symlinks:

```424:432:src/utils/claudemd.ts
async function safelyReadMemoryFileAsync(
  filePath: string,
  type: MemoryType,
  includeBasePath?: string,
): Promise<{ info: MemoryFileInfo | null; includePaths: string[] }> {
  try {
    const fs = getFsImplementation()
    const rawContent = await fs.readFile(filePath, { encoding: 'utf-8' })
```

`pathInWorkingPath` / `getExternalClaudeMdIncludes` likewise use lexical paths, so symlink targets never appear in the external-includes warning.

### Attack path

1. Attacker publishes a repo where `CLAUDE.md` is a git symlink (`120000`) to `~/.ssh/id_rsa`, **or** `CLAUDE.md` contains `@./docs/architecture.md` and `docs/architecture.md` is a symlink to a sensitive absolute path.
2. Victim clones and starts Claude Code in that directory (default project memory load; nested loads use `includeExternal: false`).
3. Lexical path stays under the project → `isExternal` is false → no external-include approval dialog.
4. `readFile` follows the symlink; secret file bytes are injected into the model context as project instructions / nested memory.
5. Prompt injection in the same tree can then exfiltrate via allowed tools (e.g. WebFetch to an attacker domain after user/domain allow, or other channels).

### Impact

Arbitrary local file read without the FileReadTool ask flow and without the CLAUDE.md external-include consent dialog. Realistic targets: SSH keys, cloud credentials, `~/.claude/settings.json`, `/etc/passwd`.

### Remediation

- After resolving each memory/`@include` path, run `realpath` / `getPathsForPermissionCheck` and treat **any** resolved form outside `getOriginalCwd()` as external (require approval), including when the lexical path is in-tree.
- Reject instruction files whose final realpath escapes the intended root.
- Prefer `lstat` + refuse symlinks (or open with `O_NOFOLLOW`) for CLAUDE.md / rules / `@include` targets.

---

## Finding 2 — Agent-memory write carve-out ignores symlink targets

| Field | Value |
| --- | --- |
| **Severity** | HIGH |
| **Location** | `src/utils/permissions/filesystem.ts` |
| **CWE** | CWE-59 / CWE-22 |

### Evidence

Write permission checks deny rules against symlink-expanded paths, then **early-allows** internal paths using only the lexical expanded path:

```1219:1250:src/utils/permissions/filesystem.ts
  // 1. Check for deny rules - check both the original path and resolved symlink path
  const pathsToCheck =
    precomputedPathsToCheck ?? getPathsForPermissionCheck(path)
  for (const pathToCheck of pathsToCheck) {
    const denyRule = matchingRuleForInput(
      pathToCheck,
      toolPermissionContext,
      'edit',
      'deny',
    )
    // ...
  }

  // 1.5. Allow writes to internal editable paths (plan files, scratchpad)
  // This MUST come before isDangerousFilePathToAutoEdit check since .claude is a dangerous directory
  const absolutePathForEdit = expandPath(path)
  const internalEditResult = checkEditableInternalPath(
    absolutePathForEdit,
    input,
  )
  if (internalEditResult.behavior !== 'passthrough') {
    return internalEditResult
  }
```

Agent-memory membership is lexical prefix only:

```68:83:src/tools/AgentTool/agentMemory.ts
export function isAgentMemoryPath(absolutePath: string): boolean {
  // SECURITY: Normalize to prevent path traversal bypasses via .. segments
  const normalizedPath = normalize(absolutePath)
  const memoryBase = getMemoryBaseDir()

  // User scope: check memory base (may be custom dir or config home)
  if (normalizedPath.startsWith(join(memoryBase, 'agent-memory') + sep)) {
    return true
  }

  // Project scope: always cwd-based (not redirected)
  if (
    normalizedPath.startsWith(join(getCwd(), '.claude', 'agent-memory') + sep)
  ) {
    return true
  }
```

```1554:1562:src/utils/permissions/filesystem.ts
  if (isAgentMemoryPath(normalizedPath)) {
    return {
      behavior: 'allow',
      updatedInput: input,
      decisionReason: {
        type: 'other',
        reason: 'Agent memory files are allowed for writing',
      },
    }
  }
```

`writeTextContent` follows symlinks (`src/utils/file.ts`). Contrast: job-dir carve-out already validates every resolved form (~1514–1548); team memory has symlink checks (`src/memdir/teamMemPaths.ts`, PSR M22186). Agent memory does not.

Project-scoped agent memory lives under `.claude/agent-memory/` and can be committed.

### Attack path

1. Malicious repo commits `.claude/agent-memory/<agentType>/note.md` as a symlink to `~/.ssh/authorized_keys` or `~/.claude/settings.json`.
2. Session uses (or is steered into) a project-scoped memory agent; model Reads then Writes that path (Read-before-Write is also auto-allowed via `checkReadableInternalPath` → `isAgentMemoryPath`).
3. `checkWritePermissionForTool` hits the agent-memory carve-out and returns `allow` before `checkPathSafetyForAutoEdit` / `DANGEROUS_DIRECTORIES`.
4. Write follows the symlink → attacker-controlled content lands on the sensitive target.

### Impact

Arbitrary file write bypassing the dangerous-path ask model: SSH `authorized_keys`, Claude settings/hooks, shell rc files, etc.

### Remediation

- Before allowing `isAgentMemoryPath` / `isAutoMemPath` carve-outs, require every path from `getPathsForPermissionCheck(absolutePath)` to remain under the real memory directory (same pattern as the job-dir hijack guard).
- Refuse writes through symlinks under these roots (`O_NOFOLLOW` / lstat).

---

## Near-misses discarded

| Candidate | Why discarded |
| --- | --- |
| WebFetch SSRF to `169.254.169.254` / localhost | `validateURL` does not block private IPs (`src/tools/WebFetchTool/utils.ts` ~139–168), but non-preapproved hosts still require permission `ask`; HTTP→HTTPS upgrade blunts classic IMDSv1. Not a silent permission bypass. |
| WebFetch open redirect to evil host | `maxRedirects: 0` + `isPermittedRedirect` same-host only; cross-host returns redirect info for a new fetch + new permission. |
| DNS rebinding after domain allow | Residual after user/domain approval; not an unaided bypass of the permission model. |
| FileRead/Write/Glob/Grep `../` traversal | `expandPath` + `getPathsForPermissionCheck` + `pathInAllowedWorkingPath` (all resolved forms must stay in working dirs for auto-allow). |
| Project `@~/secrets` includes | Blocked unless `hasClaudeMdExternalIncludesApproved`. |
| `@-mention` of `~/.ssh/...` in pasted text | `attachments.ts` only checks deny rules before `FileReadTool.call`; likely intentional user-attach UX. Paste-injection residual, not a silent tool/model path. |
| `autoMemoryDirectory` in project settings | Explicitly excluded from trusted sources in `src/memdir/paths.ts`. |
| NotebookEditTool | Uses `checkWritePermissionForTool`; no unique bypass beyond Finding 2 carve-outs. |
| WebSearchTool | Server-side Anthropic web search; no client-side URL fetch sink. |
| MCP resource URIs | Content comes from the connected MCP server, not local FS permission checks. |
| `teamMemPaths` symlink write | Already hardened with realpath containment (PSR M22186). |

---

## Out of scope / not validated as MEDIUM+

- Bash/PowerShell sandbox escape (not in the requested focus beyond path helpers).
- Prompt-injection-only exfil that still requires a user to approve WebFetch/Bash for a new domain/command.
