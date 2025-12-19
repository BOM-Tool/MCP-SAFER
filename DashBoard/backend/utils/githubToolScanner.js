/**
 * GitHub 리포지토리에서 MCP Tool 목록을 스캔하는 유틸리티 (Node.js)
 * - 서버 실행 없이 정적 분석으로 "정확한" tool 이름 추출을 지향
 * - GitHub API 사용 시 레이트리밋 완화를 위해 GITHUB_TOKEN 사용 권장
 *   (export GITHUB_TOKEN=ghp_xxx)
 */

// ---------------------------------------------------------
// SSL 인증서 문제 해결 (개발 환경에서만)
// 프로덕션에서는 절대 사용하지 마세요!
// ---------------------------------------------------------
if (process.env.NODE_ENV !== 'production') {
  // 개발 환경에서 SSL 검증 비활성화
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  // SSL 검증 비활성화 (로그 제거)
}

// ---------------------------------------------------------
// fetch 준비 (Node 18+ 기본 fetch, 그외 node-fetch)
// ---------------------------------------------------------
let fetchFn = null;
try {
  if (typeof globalThis.fetch === "function") {
    fetchFn = globalThis.fetch.bind(globalThis);
  } else {
    fetchFn = require("node-fetch");
  }
} catch {
  console.warn("[githubToolScanner] fetch가 없습니다. Node.js 18+ 사용 또는 node-fetch 설치 필요.");
}

function assertFetch() {
  if (!fetchFn) throw new Error("fetch가 사용할 수 없습니다.");
  return fetchFn;
}

// ---------------------------------------------------------
// 공통: GitHub API 호출 유틸
// ---------------------------------------------------------
async function ghFetch(url, token) {
  const fetch = assertFetch();
  const headers = { "User-Agent": "mcp-tool-scanner" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(url, { headers });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`${url} -> ${res.status} ${res.statusText} ${body ? `\n${body}` : ""}`);
  }
  return res.json();
}

// ---------------------------------------------------------
// GitHub URL 파싱
// ---------------------------------------------------------
/**
 * GitHub URL에서 owner/repo/branch 추출
 * @param {string} url
 * @returns {{owner:string, repo:string, branch?:string} | null}
 */
function parseGitHubUrl(url) {
  if (!url) return null;
  const u = url.replace(/\.git$/i, "");

  // owner/repo 형식만 들어올 수도 있음
  const short = u.match(/^([^/]+)\/([^/]+)$/);
  if (short) return { owner: short[1], repo: short[2], branch: "main" };

  // https://github.com/owner/repo/tree/branch
  const m1 = u.match(/github\.com\/([^/]+)\/([^/]+)\/tree\/([^/]+)(?:$|\/)/i);
  if (m1) return { owner: m1[1], repo: m1[2], branch: m1[3] };

  // https://github.com/owner/repo
  const m2 = u.match(/github\.com\/([^/]+)\/([^/]+)(?:$|\/)/i);
  if (m2) return { owner: m2[1], repo: m2[2], branch: "main" };

  return null;
}

// ---------------------------------------------------------
// 브랜치/트리 해석
// ---------------------------------------------------------
async function resolveBranch(owner, repo, branch) {
  const token = process.env.GITHUB_TOKEN;
  if (branch) return branch;

  // repo의 default_branch 우선
  const repoInfo = await ghFetch(`https://api.github.com/repos/${owner}/${repo}`, token);
  return repoInfo.default_branch || "main";
}

/**
 * 리포지토리 전체 트리(파일 목록) 가져오기
 * - /branches/:branch 로 tree SHA를 얻은 뒤 /git/trees/:tree_sha?recursive=1 사용
 */
async function fetchRepositoryTree(owner, repo, branch = "main") {
  const token = process.env.GITHUB_TOKEN;
  const fetch = assertFetch();
  const resolved = await resolveBranch(owner, repo, branch);

  // 올바른 엔드포인트: /branches/:branch
  const br = await ghFetch(`https://api.github.com/repos/${owner}/${repo}/branches/${resolved}`, token);
  const treeSha = br?.commit?.commit?.tree?.sha;
  if (!treeSha) throw new Error("tree sha를 찾지 못했습니다.");

  const tree = await ghFetch(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${treeSha}?recursive=1`,
    token
  );
  return tree.tree || [];
}

/**
 * Raw 파일 내용 가져오기 (브랜치 자동 해석)
 */
async function fetchGitHubFile(owner, repo, path, branch = "main") {
  const fetch = assertFetch();
  const token = process.env.GITHUB_TOKEN;
  const headers = { "User-Agent": "mcp-tool-scanner" };
  if (token) headers.Authorization = `Bearer ${token}`;

  const resolved = await resolveBranch(owner, repo, branch);

  // 순서: resolved -> main -> master
  const tryGet = async (b) => {
    const url = `https://raw.githubusercontent.com/${owner}/${repo}/${b}/${path}`;
    const res = await fetch(url, { headers });
    if (res.ok) return res.text();
    return null;
  };

  return (await tryGet(resolved)) || (resolved !== "main" && (await tryGet("main"))) || (await tryGet("master"));
}

// ---------------------------------------------------------
// 언어 감지 + 파일 선정
// ---------------------------------------------------------
function detectLanguage(files) {
  const exts = files.map((f) => (f.path || "").split(".").pop()?.toLowerCase());
  const counts = {
    go: exts.filter((e) => e === "go").length,
    py: exts.filter((e) => e === "py").length,
    ts: exts.filter((e) => e === "ts").length,
    js: exts.filter((e) => e === "js").length,
    json: exts.filter((e) => e === "json").length
  };
  const max = Math.max(...Object.values(counts));
  if (counts.go === max) return "go";
  if (counts.py === max) return "python";
  if (counts.ts === max) return "typescript";
  if (counts.js === max) return "javascript";
  if (counts.json === max) return "json";
  return "unknown";
}

/**
 * 우선순위 파일(README 최우선 + 대표 엔트리포인트) → 이후 전체 스캔 fallback
 */
function getPriorityFiles(files, language) {
  const out = [];
  const exclude = /(node_modules|\.git|__pycache__|dist\/|build\/|\.cache|\.idea|\.vscode)/i;

  const filtered = files.filter((f) => f.type === "blob" && !exclude.test(f.path || ""));

  const pushMatches = (patterns) => {
    for (const pat of patterns) {
      const matched = filtered.filter((f) => pat.test(f.path || ""));
      out.push(...matched);
    }
  };

  // README 최우선
  const readmes = filtered.filter(
    (f) => /readme/i.test(f.path || "") && (/\.(md|txt)$/i.test(f.path || "") || !/\./.test(f.path || ""))
  );
  out.push(...readmes);

  // 언어별 대표 파일
  if (language === "go") {
    pushMatches([
      /^cmd\/.*\/main\.go$/i,
      /^main\.go$/i,
      /^pkg\/.*\.go$/i,
      /^internal\/.*\.go$/i
    ]);
  } else if (language === "python") {
    pushMatches([/^src\/server\.py$/i, /^server\.py$/i, /^mcp_server\.py$/i, /^main\.py$/i, /^src\/main\.py$/i, /^src\/tools\.py$/i, /^tools\.py$/i]);
  } else if (language === "typescript" || language === "javascript") {
    pushMatches([
      /^src\/index\.(ts|js)$/i,
      /^index\.(ts|js)$/i,
      /^src\/server\.(ts|js)$/i,
      /^src\/tools\.(ts|js)$/i
    ]);
  }

  // 스키마/매니페스트는 항상 포함
  pushMatches([/tools?\.json$/i, /schema\.json$/i, /\.ya?ml$/i]);

  // 중복 제거
  const seen = new Set();
  const uniq = [];
  for (const f of out) {
    if (!seen.has(f.path)) {
      seen.add(f.path);
      uniq.push(f);
    }
  }
  return uniq;
}

function getAllLanguageFiles(files, limit = 3000) {
  const ok = /\.(go|py|ts|js|json|ya?ml|md)$/i;
  const exclude = /(node_modules|\.git|__pycache__|dist\/|build\/|\.cache|\.idea|\.vscode)/i;
  const arr = files.filter((f) => f.type === "blob" && ok.test(f.path || "") && !exclude.test(f.path || ""));
  return arr.slice(0, limit);
}

// ---------------------------------------------------------
// 추출기: Python
// ---------------------------------------------------------
function extractToolsFromPython(content) {
  const tools = new Set();

  // @tool(name="...") 또는 @mcp.tool("...") / def 바로 아래
  for (const m of content.matchAll(/@(mcp\.)?tool\s*\(\s*(?:name\s*=\s*)?["']([A-Za-z0-9_\-]+)["']\s*\)\s*\n\s*def\s+\w+/g)) {
    tools.add(m[2]);
  }
  // @tool / @mcp.tool 데코레이터 다음 줄의 def 이름을 그대로 tool 이름으로 쓰는 패턴
  for (const m of content.matchAll(/@(mcp\.)?tool\s*\)\s*\n\s*def\s+([A-Za-z0-9_]+)/g)) {
    tools.add(m[2]);
  }
  // tools = ["name", "name2"] 같은 단순 배열 리터럴
  const list = content.match(/tools\s*=\s*\[([\s\S]*?)\]/m);
  if (list) {
    for (const m of list[1].matchAll(/["']([A-Za-z0-9_\-]+)["']/g)) tools.add(m[1]);
  }
  // ToolSchema(... name="...") 류
  for (const m of content.matchAll(/ToolSchema\([^)]*?\bname\s*=\s*["']([A-Za-z0-9_\-]+)["']/g)) {
    tools.add(m[1]);
  }
  return [...tools];
}

// ---------------------------------------------------------
// 추출기: TypeScript/JavaScript
// ---------------------------------------------------------
function extractToolsFromTS(content) {
  const tools = new Set();

  // 객체 리터럴 { name: "..." }
  for (const m of content.matchAll(/\bname\s*:\s*["']([A-Za-z0-9_\-]+)["']/g)) tools.add(m[1]);

  // registerTool("..."), defineTool("..."), addTool("...")
  for (const m of content.matchAll(/\b(registerTool|defineTool|createTool|addTool)\s*\(\s*["']([A-Za-z0-9_\-]+)["']/g))
    tools.add(m[2]);

  // tools: [{ name: "..." }, ...]
  const arr = content.match(/\btools\s*:\s*\[([\s\S]*?)\]/m);
  if (arr) {
    for (const m of arr[1].matchAll(/\bname\s*:\s*["']([A-Za-z0-9_\-]+)["']/g)) tools.add(m[1]);
  }
  return [...tools];
}

// ---------------------------------------------------------
// 추출기: Go (보강)
// ---------------------------------------------------------
function extractToolsFromGo(content) {
  const out = new Set();

  // 1) map[string]Something{ "tool_name": {...}, "tool2": {...} }
  for (const m of content.matchAll(/map\s*\[\s*string\s*]\s*\w*\s*\{([\s\S]*?)\}/gm)) {
    const body = m[1];
    for (const k of body.matchAll(/["'`](?<name>[A-Za-z0-9_\-]+)["'`]\s*:/g)) {
      out.add(k.groups.name);
    }
  }

  // 2) struct 리터럴 내 Name/ID/Slug: "..."
  for (const m of content.matchAll(/\{[^{}]*\b(Name|ID|Slug)\s*:\s*["'`](?<name>[A-Za-z0-9_\-]+)["'`][^{}]*\}/gm)) {
    out.add(m.groups.name);
  }

  // 3) Register/Add/New Tool 호출
  for (const m of content.matchAll(/\b(Register|Add|New)Tool[s]?\s*\(\s*["'`](?<name>[A-Za-z0-9_\-]+)["'`]/g)) {
    out.add(m.groups.name);
  }

  // 4) []ToolSpec{ {Name:"..."}, {ID:"..."} }
  for (const m of content.matchAll(/\[\]\s*\w+\s*\{([\s\S]*?)\}/gm)) {
    const body = m[1];
    for (const n of body.matchAll(/\b(Name|ID|Slug)\s*:\s*["'`](?<name>[A-Za-z0-9_\-]+)["'`]/g)) out.add(n.groups.name);
  }

  return [...out];
}

// ---------------------------------------------------------
// 추출기: JSON
// ---------------------------------------------------------
function extractToolsFromJSON(content) {
  try {
    const json = JSON.parse(content);
    const tools = new Set();
    if (Array.isArray(json.tools)) {
      for (const t of json.tools) if (t && t.name) tools.add(t.name);
    } else if (json.tools && typeof json.tools === "object") {
      for (const k of Object.keys(json.tools)) {
        const v = json.tools[k];
        if (v && v.name) tools.add(v.name);
        else tools.add(k);
      }
    }
    return [...tools];
  } catch {
    return [];
  }
}

// ---------------------------------------------------------
// 추출기: README (문서에서 이름을 "정확히" 뽑을 때만)
// ---------------------------------------------------------
function extractToolsFromReadme(content) {
  const out = new Set();

  // ## Tools 섹션 범위
  const toolsSectionMatch = content.match(/##\s+Tools\s*\n([\s\S]*?)(?=\n##\s+|$)/i);
  const toolsSection = toolsSectionMatch ? toolsSectionMatch[1] : content;

  // ###/#### Toolset 제목 줄 (콜론/설명 허용)
  const toolsetSectionPattern = /(?:###|####)\s+([^\n:]+?)(?::[^\n]*)?\s*\n([\s\S]*?)(?=\n(?:###|##|$))/g;
  let ss;
  let any = false;
  while ((ss = toolsetSectionPattern.exec(toolsSection)) !== null) {
    any = true;
    const toolsetContent = ss[2];

    // 리스트/테이블 안의 명시적 툴 이름(알파뉴메릭/_/-)
    const patterns = [
      /[-*]\s*`([A-Za-z0-9_-]+)`/g,
      /[-*]\s+([A-Za-z0-9_-]+)\s*(?:\(|:|\s|$)/g,
      /`([A-Za-z0-9_-]+)`/g,
      /\|\s*`?([A-Za-z0-9_-]+)`?\s*\|/g
    ];
    for (const p of patterns) {
      let m;
      while ((m = p.exec(toolsetContent)) !== null) {
        const name = m[1];
        if (!/^(list|get|set|add|remove|delete|create|update|tool|tools|name|description|parameter|param)$/i.test(name)) {
          out.add(name);
        }
      }
    }
  }

  // 툴셋 구분이 없어도 리스트에서 직접 추출
  if (!any) {
    for (const m of toolsSection.matchAll(/[-*]\s*`([A-Za-z0-9_-]+)`/g)) out.add(m[1]);
  }

  // 코드 블록 내 JSON/Go 예제에서도 시도
  for (const block of content.matchAll(/```(?:go|json|yaml|yml)?\s*\n([\s\S]*?)```/g)) {
    const code = block[1];
    extractToolsFromJSON(code).forEach((t) => out.add(t));
    extractToolsFromGo(code).forEach((t) => out.add(t));
  }

  return [...out].filter((t) => t.length > 2);
}

// ---------------------------------------------------------
// 메인: 리포지토리 스캔
// ---------------------------------------------------------
async function scanGitHubForTools(githubUrl) {
  const parsed = parseGitHubUrl(githubUrl);
  if (!parsed) throw new Error("유효하지 않은 GitHub URL입니다.");

  const { owner, repo, branch } = parsed;
  const tools = new Set();
  const scannedFiles = [];

  // 1) 트리 조회
  const allFiles = await fetchRepositoryTree(owner, repo, branch);

  // 2) 언어 감지
  const language = detectLanguage(allFiles);

  // 3) 우선순위 파일 (README 최우선)
  const priorityFiles = getPriorityFiles(allFiles, language);
  const readmes = priorityFiles.filter((f) => /readme/i.test(f.path || ""));
  const others = priorityFiles.filter((f) => !/readme/i.test(f.path || ""));
  const sorted = [...readmes, ...others];

  // 4) 우선순위 파일부터 스캔
  for (const file of sorted) {
    if (file.type !== "blob") continue;
    const p = file.path;
    const content = await fetchGitHubFile(owner, repo, p, branch);
    if (!content) continue;

    scannedFiles.push(p);
    let found = [];
    if (/\.go$/i.test(p)) found = extractToolsFromGo(content);
    else if (/\.py$/i.test(p)) found = extractToolsFromPython(content);
    else if (/\.(ts|js)$/i.test(p)) found = extractToolsFromTS(content);
    else if (/\.json$/i.test(p)) found = extractToolsFromJSON(content);
    else if (/readme/i.test(p)) found = extractToolsFromReadme(content);

    if (found?.length) found.forEach((t) => tools.add(t));
  }

  // 5) 아직 없으면 전체 파일 스캔 (상한 3000개)
  if (tools.size === 0) {
    const all = getAllLanguageFiles(allFiles, 3000);
    for (const file of all) {
      const p = file.path;
      const content = await fetchGitHubFile(owner, repo, p, branch);
      if (!content) continue;

      scannedFiles.push(p);
      let found = [];
      if (/\.go$/i.test(p)) found = extractToolsFromGo(content);
      else if (/\.py$/i.test(p)) found = extractToolsFromPython(content);
      else if (/\.(ts|js)$/i.test(p)) found = extractToolsFromTS(content);
      else if (/\.json$/i.test(p)) found = extractToolsFromJSON(content);
      else if (/readme/i.test(p)) found = extractToolsFromReadme(content);

      if (found?.length) found.forEach((t) => tools.add(t));
    }
  }

  // 결과
  return {
    repository: `${owner}/${repo}`,
    branch: await resolveBranch(owner, repo, branch),
    tools: [...tools].sort(),
    files: scannedFiles
  };
}

// ---------------------------------------------------------
// 레거시(미사용 가능): 고정 경로만 훑는 단순 스캐너
// ---------------------------------------------------------
async function scanGitHubForToolsLegacy(githubUrl) {
  const parsed = parseGitHubUrl(githubUrl);
  if (!parsed) throw new Error("유효하지 않은 GitHub URL입니다.");
  const { owner, repo, branch } = parsed;

  const tryFiles = [
    // Python
    "src/server.py", "server.py", "mcp_server.py", "main.py", "src/main.py", "src/tools.py", "tools.py",
    // TS/JS
    "src/index.ts", "src/index.js", "index.ts", "index.js", "src/server.ts", "src/server.js", "src/tools.ts", "src/tools.js",
    // Schema
    "schema.json", "tools.json", "src/schema.json",
    // Docs
    "README.md"
  ];

  const tools = new Set();
  const scanned = [];

  for (const p of tryFiles) {
    const content = await fetchGitHubFile(owner, repo, p, branch);
    if (!content) continue;

    scanned.push(p);
    let found = [];
    if (/\.py$/i.test(p)) found = extractToolsFromPython(content);
    else if (/\.(ts|js)$/i.test(p)) found = extractToolsFromTS(content);
    else if (/\.json$/i.test(p)) found = extractToolsFromJSON(content);
    else if (/readme/i.test(p)) found = extractToolsFromReadme(content);

    if (found?.length) {
      found.forEach((t) => tools.add(t));
      // 필요 시 즉시 종료 가능
      // break;
    }
  }

  return {
    repository: `${owner}/${repo}`,
    branch,
    tools: [...tools].sort(),
    files: scanned
  };
}

// ---------------------------------------------------------
// exports
// ---------------------------------------------------------
module.exports = {
  scanGitHubForTools,
  scanGitHubForToolsLegacy,
  parseGitHubUrl,
  fetchRepositoryTree, // 필요 시 개별 호출
  fetchGitHubFile      // 필요 시 개별 호출
};
