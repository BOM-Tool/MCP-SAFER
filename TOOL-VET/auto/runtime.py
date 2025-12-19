from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence


@dataclass
class RuntimePlan:
    """설치 및 서버 실행에 필요한 정보를 담는 계획."""

    name: str
    install_steps: List[Sequence[str]] = field(default_factory=list)
    server_command: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    work_dir: Optional[Path] = None
    notes: Optional[str] = None
    transport_type: str = "stdio"
    http_port: Optional[int] = None
    http_url: Optional[str] = None


def detect_runtime(repo_root: Path) -> RuntimePlan:
    """저장소에서 사용 언어를 감지하고 실행 계획을 생성."""

    repo_root = repo_root.resolve()

    detectors: List[_RuntimeDetector] = [
        _GoRuntimeDetector(),
        _NpmRuntimeDetector(),
    ]

    for detector in detectors:
        if detector.detect(repo_root):
            plan = detector.create_plan(repo_root)
            if plan.server_command:
                return plan

    raise RuntimeError(
        "지원되는 런타임을 찾지 못했습니다. "
        "(현재 Go 모듈(go.mod) 또는 npm(package.json) 프로젝트만 지원합니다.)"
    )


class _RuntimeDetector:
    def detect(self, repo_root: Path) -> bool:
        raise NotImplementedError

    def create_plan(self, repo_root: Path) -> RuntimePlan:
        raise NotImplementedError


class _GoRuntimeDetector(_RuntimeDetector):
    def detect(self, repo_root: Path) -> bool:
        if (repo_root / "go.mod").exists():
            return True
        
        exclude_dirs = {"vendor", "node_modules", ".git", "testdata", "tests", "examples"}
        for item in repo_root.iterdir():
            if item.is_dir() and item.name not in exclude_dirs:
                if (item / "go.mod").exists():
                    return True
                try:
                    for subitem in item.iterdir():
                        if subitem.is_dir() and subitem.name not in exclude_dirs:
                            if (subitem / "go.mod").exists():
                                return True
                except PermissionError:
                    pass
        
        return False

    def create_plan(self, repo_root: Path) -> RuntimePlan:
        go_mod_dir = self._find_go_mod_dir(repo_root)
        if not go_mod_dir:
            go_mod_dir = repo_root
        
        install_steps: List[Sequence[str]] = [["go", "mod", "download"]]
        if go_mod_dir != repo_root:
            install_steps = [["go", "mod", "download", "-C", str(go_mod_dir)]]

        server_command = self._guess_server_command(go_mod_dir)
        env = {}

        return RuntimePlan(
            name="go",
            install_steps=install_steps,
            server_command=server_command,
            env=env,
            work_dir=go_mod_dir,
            notes=f"Go 모듈 프로젝트 자동 실행 (디렉터리: {go_mod_dir.name})",
        )
    
    def _find_go_mod_dir(self, repo_root: Path) -> Optional[Path]:
        if (repo_root / "go.mod").exists():
            return repo_root
        
        exclude_dirs = {"vendor", "node_modules", ".git", "testdata", "tests", "examples"}
        for item in repo_root.iterdir():
            if item.is_dir() and item.name not in exclude_dirs:
                if (item / "go.mod").exists():
                    return item
                try:
                    for subitem in item.iterdir():
                        if subitem.is_dir() and subitem.name not in exclude_dirs:
                            if (subitem / "go.mod").exists():
                                return subitem
                except PermissionError:
                    pass
        
        return None

    @staticmethod
    def _guess_server_command(repo_root: Path) -> List[str]:
        # mcp-filesystem-server는 디렉토리 경로 인자가 필요 (stdio 대신)
        # repo_root.name이 "repo"일 수 있으므로 go.mod의 module 이름도 확인
        repo_name = repo_root.name.lower()
        go_mod_path = repo_root / "go.mod"
        module_name = ""
        if go_mod_path.exists():
            try:
                content = go_mod_path.read_text(encoding="utf-8")
                for line in content.split("\n"):
                    if line.startswith("module"):
                        module_name = line.split()[-1].lower()
                        break
            except Exception:
                pass
        
        if "filesystem" in repo_name or "filesystem-server" in repo_name or "filesystem" in module_name:
            # 임시 디렉토리 경로 제공
            temp_dir = repo_root / "tmp"
            temp_dir.mkdir(exist_ok=True)
            if (repo_root / "main.go").exists():
                return ["go", "run", ".", str(temp_dir)]
            # 다른 경로들도 체크
            cmd_dir = repo_root / "cmd"
            if cmd_dir.is_dir():
                candidates = [
                    path
                    for path in cmd_dir.iterdir()
                    if path.is_dir() and (path / "main.go").exists()
                ]
                if candidates:
                    rel = candidates[0].relative_to(repo_root)
                    return ["go", "run", f"./{rel}", str(temp_dir)]
            return ["go", "run", "./...", str(temp_dir)]
        
        # 일반적인 MCP 서버는 stdio 사용
        cmd_dir = repo_root / "cmd"
        if cmd_dir.is_dir():
            candidates = [
                path
                for path in cmd_dir.iterdir()
                if path.is_dir() and (path / "main.go").exists()
            ]
            if len(candidates) == 1:
                rel = candidates[0].relative_to(repo_root)
                return ["go", "run", f"./{rel}", "stdio"]
            if len(candidates) > 1:
                preferred = _select_preferred(
                    candidates,
                    ("mcp-server", "server", "mcp", "cmd"),
                )
                if preferred:
                    rel = preferred.relative_to(repo_root)
                    return ["go", "run", f"./{rel}", "stdio"]
                rel = candidates[0].relative_to(repo_root)
                return ["go", "run", f"./{rel}", "stdio"]

        if (repo_root / "main.go").exists():
            return ["go", "run", ".", "stdio"]

        internal_dir = repo_root / "internal"
        if internal_dir.is_dir():
            candidates = _find_main_go_dirs(internal_dir)
            if candidates:
                preferred = _select_preferred(
                    candidates,
                    ("server", "mcp", "cmd", "main"),
                )
                if preferred:
                    rel = preferred.relative_to(repo_root)
                    return ["go", "run", f"./{rel}", "stdio"]
                rel = candidates[0].relative_to(repo_root)
                return ["go", "run", f"./{rel}", "stdio"]

        pkg_dir = repo_root / "pkg"
        if pkg_dir.is_dir():
            candidates = _find_main_go_dirs(pkg_dir)
            if candidates:
                preferred = _select_preferred(
                    candidates,
                    ("server", "mcp", "cmd", "main"),
                )
                if preferred:
                    rel = preferred.relative_to(repo_root)
                    return ["go", "run", f"./{rel}", "stdio"]
                rel = candidates[0].relative_to(repo_root)
                return ["go", "run", f"./{rel}", "stdio"]

        candidates = _find_main_go_dirs(repo_root, max_depth=2)
        if candidates:
            preferred = _select_preferred(
                candidates,
                ("mcp", "server", "cmd", "main"),
            )
            if preferred:
                rel = preferred.relative_to(repo_root)
                return ["go", "run", f"./{rel}", "stdio"]
            rel = candidates[0].relative_to(repo_root)
            return ["go", "run", f"./{rel}", "stdio"]

        try:
            import subprocess
            result = subprocess.run(
                ["go", "list", "-f", "{{.ImportPath}}", "./..."],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                packages = result.stdout.strip().split("\n")
                for pkg in packages:
                    if pkg and not pkg.endswith("/..."):
                        pkg_path = repo_root / pkg.replace(repo_root.name, "").lstrip("/")
                        if (pkg_path / "main.go").exists():
                            rel = pkg_path.relative_to(repo_root)
                            return ["go", "run", f"./{rel}", "stdio"]
        except (subprocess.SubprocessError, FileNotFoundError, TimeoutError):
            pass

        return ["go", "run", "./...", "stdio"]


def _find_main_go_dirs(root: Path, max_depth: int = 3, current_depth: int = 0) -> List[Path]:
    candidates: List[Path] = []
    
    if current_depth >= max_depth:
        return candidates
    
    if not root.is_dir():
        return candidates
    
    if (root / "main.go").exists():
        candidates.append(root)
    
    exclude_dirs = {"vendor", "node_modules", ".git", "testdata", "tests", "examples"}
    try:
        for item in root.iterdir():
            if item.is_dir() and item.name not in exclude_dirs:
                candidates.extend(_find_main_go_dirs(item, max_depth, current_depth + 1))
    except PermissionError:
        pass
    
    return candidates


class _NpmRuntimeDetector(_RuntimeDetector):
    def detect(self, repo_root: Path) -> bool:
        return (repo_root / "package.json").exists()

    def create_plan(self, repo_root: Path) -> RuntimePlan:
        package_json_path = repo_root / "package.json"
        data = json.loads(package_json_path.read_text(encoding="utf-8"))

        install_steps: List[Sequence[str]] = [["npm", "install"]]

        scripts: Dict[str, str] = data.get("scripts", {})
        if "build" in scripts:
            install_steps.append(["npm", "run", "build"])

        # monorepo 감지 및 특정 서버 디렉토리 찾기
        workspaces = data.get("workspaces", [])
        if workspaces or data.get("name", "").startswith("@modelcontextprotocol/servers"):
            # monorepo인 경우 특정 서버 디렉토리 찾기
            server_dir = self._find_server_directory(repo_root)
            if server_dir and server_dir != repo_root:
                # 특정 서버 디렉토리에서 실행
                server_package_json = server_dir / "package.json"
                if server_package_json.exists():
                    server_data = json.loads(server_package_json.read_text(encoding="utf-8"))
                    server_command, transport_type, http_port = self._guess_server_command(server_dir, server_data)
                    return RuntimePlan(
                        name="npm",
                        install_steps=install_steps,
                        server_command=server_command,
                        env={},
                        notes=f"npm monorepo 프로젝트 자동 실행 (서버: {server_dir.name})",
                        transport_type=transport_type,
                        http_port=http_port,
                        http_url=f"http://127.0.0.1:{http_port}" if transport_type == "http" and http_port else None,
                        work_dir=server_dir,
                    )

        server_command, transport_type, http_port = self._guess_server_command(repo_root, data)

        http_url = None
        if transport_type == "http" and http_port:
            http_url = f"http://127.0.0.1:{http_port}"

        notes = "npm 프로젝트 자동 실행"
        if transport_type == "http":
            notes = f"npm 프로젝트 자동 실행 (HTTP transport, 포트 {http_port})"

        return RuntimePlan(
            name="npm",
            install_steps=install_steps,
            server_command=server_command,
            env={},
            notes=notes,
            transport_type=transport_type,
            http_port=http_port,
            http_url=http_url,
        )

    def _guess_server_command(self, repo_root: Path, package_data: Dict) -> tuple[List[str], str, Optional[int]]:
        scripts: Dict[str, str] = package_data.get("scripts", {})
        bin_entries = package_data.get("bin")

        if isinstance(bin_entries, dict) and bin_entries:
            executable = next(iter(bin_entries.values()))
            bin_name = next(iter(bin_entries.keys()))
            if executable:
                executable_path = repo_root / executable
                if executable_path.exists():
                    if executable_path.suffix == ".mjs":
                        return (["node", str(executable_path)], "stdio", None)
                    if executable_path.suffix == ".js":
                        return (["node", str(executable_path)], "stdio", None)
                    if executable_path.suffix in {".ts", ".tsx"}:
                        return (["npx", "--yes", "tsx", str(executable_path), "--transport", "stdio"], "stdio", None)
                    return (["node", str(executable_path)], "stdio", None)
                package_name = package_data.get("name", "")
                description = package_data.get("description", "").lower()
                # bin 이름, package 이름, 또는 description에 http/streamablehttp가 있으면 HTTP transport
                if "http" in bin_name.lower() or "http" in package_name.lower() or "streamablehttp" in description or ("http" in description and "transport" in description):
                    if package_name.startswith("@"):
                        # mcp-google-map의 경우 --apikey 옵션 필요 (환경변수로 전달됨)
                        return (["npx", "--yes", package_name, "--port", "3000"], "http", 3000)
                    return (["npx", "--yes", bin_name, "--port", "3000"], "http", 3000)
                return (["npx", "--yes", bin_name], "stdio", None)

        for key in ("start", "serve", "start:cli"):
            if key in scripts:
                script_cmd = scripts[key]
                if "--transport" in script_cmd and "http" in script_cmd.lower():
                    return (["npm", "run", key], "http", 3000)
                if "--transport" in script_cmd or "--stdio" in script_cmd:
                    return (["npm", "run", key], "stdio", None)
                return (["npm", "run", key, "--", "--transport", "stdio"], "stdio", None)

        main_field = package_data.get("main")
        if main_field:
            main_path = repo_root / main_field
            if main_path.exists():
                if main_path.suffix in {".ts", ".tsx"}:
                    return (["npx", "--yes", "tsx", str(main_path), "--transport", "stdio"], "stdio", None)
                return (["node", str(main_path), "--transport", "stdio"], "stdio", None)

        dist_dir = repo_root / "dist"
        if dist_dir.is_dir():
            for candidate_name in ("cli.js", "index.js", "server.js", "main.js"):
                candidate_path = dist_dir / candidate_name
                if candidate_path.exists():
                    return (["node", str(candidate_path), "--transport", "stdio"], "stdio", None)

        src_dir = repo_root / "src"
        if src_dir.is_dir():
            for candidate_name in ("cli.ts", "index.ts", "server.ts", "main.ts"):
                candidate_path = src_dir / candidate_name
                if candidate_path.exists():
                    return (["npx", "--yes", "tsx", str(candidate_path), "--transport", "stdio"], "stdio", None)

        for candidate_name in ("cli.js", "index.js", "server.js", "main.js"):
            candidate_path = repo_root / candidate_name
            if candidate_path.exists():
                return (["node", str(candidate_path), "--transport", "stdio"], "stdio", None)

        package_name = package_data.get("name", "")
        description = package_data.get("description", "").lower()
        if package_name:
            # package name이나 description에 http/streamablehttp가 있으면 HTTP transport
            if "http" in package_name.lower() or "streamablehttp" in description or ("http" in description and "transport" in description):
                return (["npx", "--yes", package_name, "--port", "3000"], "http", 3000)
            return (["npx", "--yes", package_name, "--transport", "stdio"], "stdio", None)

        raise RuntimeError("npm 프로젝트에서 실행할 커맨드를 찾지 못했습니다.")

    def _find_server_directory(self, repo_root: Path) -> Optional[Path]:
        """monorepo에서 특정 서버 디렉토리를 찾습니다."""
        # src 디렉토리 내의 서버 디렉토리 찾기
        src_dir = repo_root / "src"
        if src_dir.is_dir():
            # 일반적인 서버 디렉토리 이름 패턴
            server_patterns = ["notion", "slack", "filesystem", "memory", "sequential-thinking", "everything"]
            for pattern in server_patterns:
                server_dir = src_dir / pattern
                if server_dir.is_dir() and (server_dir / "package.json").exists():
                    return server_dir
            
            # src 디렉토리 내의 모든 디렉토리 확인
            try:
                for item in src_dir.iterdir():
                    if item.is_dir() and (item / "package.json").exists():
                        # package.json에 bin이나 main이 있는지 확인
                        try:
                            server_data = json.loads((item / "package.json").read_text(encoding="utf-8"))
                            if server_data.get("bin") or server_data.get("main"):
                                return item
                        except:
                            pass
            except PermissionError:
                pass
        
        # packages 디렉토리 확인 (일부 monorepo 구조)
        packages_dir = repo_root / "packages"
        if packages_dir.is_dir():
            try:
                for item in packages_dir.iterdir():
                    if item.is_dir() and (item / "package.json").exists():
                        try:
                            server_data = json.loads((item / "package.json").read_text(encoding="utf-8"))
                            if server_data.get("bin") or server_data.get("main"):
                                return item
                        except:
                            pass
            except PermissionError:
                pass
        
        return None


def _select_preferred(paths: Iterable[Path], keywords: Iterable[str]) -> Optional[Path]:
    for keyword in keywords:
        for path in paths:
            if keyword in path.name:
                return path
    return None

