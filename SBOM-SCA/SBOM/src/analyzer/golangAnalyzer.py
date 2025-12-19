#!/usr/bin/env python3
"""
Enhanced Go Module Dependency Analyzer
Analyzes Go module dependencies using go mod graph and go list -m all
"""

import json
import subprocess
import os
from pathlib import Path
from typing import Dict, Any, List, Set, Tuple, Optional


class GolangAnalyzer:
    """Enhanced Go module dependency analyzer using go mod graph"""
    
    def __init__(self):
        """Initialize the enhanced Go analyzer"""
        self._stdlib_license_cache: Optional[str] = None
        self._goroot_cache: Optional[str] = None
    
    def analyze(self, target_path: str, git_url: str = None) -> Dict[str, Any]:
        """
        Analyze Go module dependencies using go mod graph
        
        Args:
            target_path: Path to the Go project to analyze
            git_url: Git URL for better root module naming
            
        Returns:
            Dictionary containing analysis results
        """
        try:
            print(f"DEBUG: Analyzing Go project at: {target_path}")
            
            go_mod_path = self._find_go_mod_file(target_path)
            if not go_mod_path:
                raise FileNotFoundError("No go.mod file found in project or subdirectories")
            
            print(f"DEBUG: Found go.mod at: {go_mod_path}")
            
            mvs_modules = self._get_mvs_selected_modules(go_mod_path)
            print(f"DEBUG: Found {len(mvs_modules)} MVS selected modules")
            
            graph_modules, graph_dependencies = self._get_graph_modules(go_mod_path)
            print(f"DEBUG: Found {len(graph_modules)} graph modules")
            print(f"DEBUG: Found {len(graph_dependencies)} dependency relationships")
            
            # Build deep dependency graph by recursively parsing each module's own go.mod requires
            deep_graph_modules, deep_graph_dependencies, deep_graph_dependencies_direct_only = self._get_deep_require_graph(go_mod_path)
            print(f"DEBUG: Found {len(deep_graph_modules)} deep graph modules")
            print(f"DEBUG: Found {sum(len(v) for v in deep_graph_dependencies.values())} deep dependency relationships (including indirect)")
            print(f"DEBUG: Found {sum(len(v) for v in deep_graph_dependencies_direct_only.values())} deep dependency relationships (direct-only)")

            root_module = self._get_root_module_with_git_context(go_mod_path, target_path, git_url)
            
            packages = []
            
            # Build MVS version map: module_name -> MVS_version
            # This ensures we use MVS selected version for each module (deduplication)
            mvs_version_map: Dict[str, str] = {}
            for mvs_module in mvs_modules:
                module_name, module_version = self._parse_module_version(mvs_module)
                if module_version:
                    # MVS selected version - always use this
                    mvs_version_map[module_name] = module_version
                else:
                    # Module without version (main module) - store empty string
                    if module_name not in mvs_version_map:
                        mvs_version_map[module_name] = ""
            
            # Deduplicate modules by name, preferring MVS selected version
            # This ensures each module appears only once with its MVS selected version
            deduplicated_modules: Dict[str, str] = {}  # module_name -> version
            
            # Collect all unique module names from both sources
            all_module_names: Set[str] = set()
            for module_full_name in list(graph_modules.keys()) + list(deep_graph_modules.keys()):
                module_name, _ = self._parse_module_version(module_full_name)
                all_module_names.add(module_name)
            
            # For each module, use MVS version if available, otherwise use version from graph/deep_graph
            for module_name in all_module_names:
                if module_name in mvs_version_map:
                    # Use MVS selected version (this is the actual version used in build)
                    deduplicated_modules[module_name] = mvs_version_map[module_name]
                else:
                    # MVS doesn't have this module - use version from graph_modules or deep_graph_modules
                    # Prefer deep_graph_modules (more comprehensive) over graph_modules
                    found_version = None
                    for module_full_name, module_version in deep_graph_modules.items():
                        mn, _ = self._parse_module_version(module_full_name)
                        if mn == module_name:
                            found_version = module_version
                            break
                    if not found_version:
                        for module_full_name, module_version in graph_modules.items():
                            mn, _ = self._parse_module_version(module_full_name)
                            if mn == module_name:
                                found_version = module_version
                                break
                    if found_version:
                        deduplicated_modules[module_name] = found_version
            
            # Convert to union_modules format for compatibility with existing code
            union_modules: Dict[str, str] = {}
            for module_name, module_version in deduplicated_modules.items():
                module_full_name = f"{module_name}@{module_version}" if module_version else module_name
                union_modules[module_full_name] = module_version

            for module_full_name, module_version in union_modules.items():
                module_name, _ = self._parse_module_version(module_full_name)
                
                # Check if this is MVS selected version
                is_mvs_selected = False
                if module_name in mvs_version_map:
                    mvs_version = mvs_version_map[module_name]
                    is_mvs_selected = (module_version == mvs_version or (not module_version and not mvs_version))
                
                actual_root_module = self._get_root_module(go_mod_path)
                print(f"DEBUG: Checking module {module_name} against root_module {root_module} and actual {actual_root_module}")
                if module_name == root_module or module_name == actual_root_module:
                    git_version = self._get_git_version(target_path)
                    if git_version:
                        module_version = git_version
                        print(f"DEBUG: Using Git version for {module_name}: {module_version}")
                    else:
                        print(f"DEBUG: No Git version found for {module_name}")
                
                package = {
                    "name": module_name,
                    "version": module_version,
                    "metadata": {
                        "is_direct": False,  
                        "is_mvs_selected": is_mvs_selected,
                    }
                }
                packages.append(package)
            
            direct_deps = self._get_direct_dependencies(go_mod_path)
            print(f"DEBUG: Found {len(direct_deps)} direct dependencies")
            
            for package in packages:
                package_name = package["name"]
                package_version = package["version"]
                package_full_name = f"{package_name}@{package_version}" if package_version else package_name
                
                if package_full_name in direct_deps:
                    package["metadata"]["is_direct"] = True

            self._populate_license_metadata(packages, target_path)

            result = {
                "root_module": root_module,
                "packages": packages,
                "dependencies": graph_dependencies,
                # Extended fields preserving backward compatibility
                "expanded_dependencies": deep_graph_dependencies,
                "expanded_dependencies_direct_only": deep_graph_dependencies_direct_only,
                "expanded_modules_count": len(deep_graph_modules),
                "mvs_selected_count": len(mvs_modules),
                "graph_modules_count": len(graph_modules),
                "direct_dependencies_count": len(direct_deps)
            }
            
            print(f"DEBUG: Analysis completed with {len(packages)} packages")
            return result
            
        except Exception as e:
            print(f"ERROR: Failed to analyze Go project: {e}")
            raise
    
    def _populate_license_metadata(self, packages: List[Dict[str, Any]], target_path: str) -> None:
        """Populate license metadata for Go modules."""
        license_cache: Dict[Tuple[str, str], Optional[str]] = {}
        for package in packages:
            metadata = package.setdefault("metadata", {})
            module_name = package.get("name", "")
            module_version = package.get("version", "")

            first_segment = module_name.split('/', 1)[0]
            if '.' not in first_segment:
                metadata.setdefault("dependency_type", "stdlib")
                license_id = self._detect_stdlib_license(target_path)
                if license_id:
                    metadata["license"] = license_id
                continue

            key = (module_name, module_version)
            if key in license_cache:
                license_id = license_cache[key]
            else:
                license_id = self._detect_module_license(target_path, module_name, module_version)
                license_cache[key] = license_id

            if license_id:
                metadata["license"] = license_id

    def _detect_stdlib_license(self, target_path: str) -> Optional[str]:
        if self._stdlib_license_cache is not None:
            return self._stdlib_license_cache

        goroot = self._get_goroot(target_path)
        if not goroot:
            self._stdlib_license_cache = None
            return None

        license_id = self._scan_license_directory(str(Path(goroot)))
        if not license_id:
            self._stdlib_license_cache = None
            return None
        self._stdlib_license_cache = license_id
        return license_id

    def _get_goroot(self, target_path: str) -> Optional[str]:
        if self._goroot_cache is not None:
            return self._goroot_cache
        try:
            result = subprocess.run(
                ["go", "env", "GOROOT"],
                cwd=target_path,
                capture_output=True,
                text=True,
                check=True
            )
            goroot = result.stdout.strip()
            self._goroot_cache = goroot or None
            return self._goroot_cache
        except subprocess.CalledProcessError as e:
            msg = e.stderr.strip() if e.stderr else str(e)
            print(f"DEBUG: Failed to get GOROOT: {msg}")
        self._goroot_cache = None
        return None

    def _detect_module_license(self, target_path: str, module_name: str, module_version: str) -> Optional[str]:
        """Detect license for a Go module by inspecting its module directory."""
        module_dir = self._get_module_dir(target_path, module_name, module_version)
        if not module_dir:
            root_module = self._get_root_module(target_path)
            if root_module and module_name == root_module:
                module_dir = target_path
            else:
                return None
        return self._scan_license_directory(module_dir)

    def _get_module_dir(self, target_path: str, module_name: str, module_version: str) -> Optional[str]:
        """Locate module directory using go list -m -json."""
        try:
            module_ref = module_name if not module_version else f"{module_name}@{module_version}"
            cmd = ["go", "list", "-m", "-json", module_ref]
            result = subprocess.run(
                cmd,
                cwd=target_path,
                capture_output=True,
                text=True,
                check=True
            )
            if not result.stdout:
                return None
            data = json.loads(result.stdout)
            return data.get("Dir")
        except subprocess.CalledProcessError as e:
            msg = e.stderr.strip() if e.stderr else str(e)
            print(f"DEBUG: Failed to get module dir for {module_name}@{module_version}: {msg}")
        except json.JSONDecodeError as e:
            print(f"DEBUG: Failed to parse go list output for {module_name}@{module_version}: {e}")
        return None

    def _scan_license_directory(self, module_dir: str) -> Optional[str]:
        """Scan module directory for common license files and map to SPDX IDs."""
        if not module_dir or not os.path.isdir(module_dir):
            return None

        current = Path(module_dir)
        visited: Set[str] = set()
        max_levels = 3
        levels = 0
        while True:
            directory_str = str(current)
            if directory_str not in visited:
                license_id = self._scan_license_files_in_dir(current)
                if license_id:
                    return license_id
                visited.add(directory_str)
            if levels >= max_levels or current.parent == current:
                break
            levels += 1
            current = current.parent
        return None

    def _scan_license_files_in_dir(self, directory: Path) -> Optional[str]:
        if not directory.exists() or not directory.is_dir():
            return None

        preferred_names = {
            "license", "license.txt", "license.md", "copying", "copying.txt",
            "copyright", "unlicense", "license-apache", "license-mit",
            "license-bsd", "notice"
        }
        candidates: List[Path] = []
        for entry in directory.iterdir():
            if not entry.is_file():
                continue
            name = entry.name.lower()
            if name in preferred_names or any(token in name for token in ("license", "copying", "copyright", "notice")):
                candidates.append(entry)

        # Ensure deterministic order
        candidates.sort(key=lambda p: p.name.lower())

        for candidate in candidates:
            license_id = self._classify_license_file(candidate)
            if license_id:
                return license_id
        return None

    def _classify_license_file(self, path: Path) -> Optional[str]:
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            print(f"DEBUG: Failed to read license file {path}: {e}")
            return None
        return self._classify_license_content(content)

    def _classify_license_content(self, content: str) -> Optional[str]:
        text = content.lower()
        license_patterns = [
            ("Apache-2.0", ["apache license", "version 2"]),
            ("Apache-2.0", ["apache license", "license-2.0"]),
            ("MIT", ["permission is hereby granted"]),
            ("BSD-3-Clause", ["redistribution and use in source and binary forms", "neither the name of"]),
            ("BSD-2-Clause", ["redistribution and use in source and binary forms", "the names of its contributors"]),
            ("ISC", ["permission to use, copy, modify, and/or distribute this software for any purpose with or without fee"]),
            ("MPL-2.0", ["mozilla public license", "version 2.0"]),
            ("LGPL-3.0-or-later", ["gnu lesser general public license", "version 3"]),
            ("LGPL-2.1-or-later", ["gnu lesser general public license", "version 2.1"]),
            ("GPL-3.0-or-later", ["gnu general public license", "version 3"]),
            ("GPL-2.0-or-later", ["gnu general public license", "version 2"]),
            ("AGPL-3.0-or-later", ["gnu affero general public license"]),
            ("Unlicense", ["this is free and unencumbered software released into the public domain"]),
            ("CC0-1.0", ["creative commons zero", "1.0"]),
            ("EPL-2.0", ["eclipse public license", "version 2.0"]),
            ("EPL-1.0", ["eclipse public license", "version 1.0"])
        ]

        for spdx_id, keywords in license_patterns:
            if all(keyword in text for keyword in keywords):
                return spdx_id
        return None

    def _get_mvs_selected_modules(self, target_path: str) -> Set[str]:
        """Get MVS selected modules using go list -m all"""
        try:
            cmd = ["go", "list", "-m", "all"]
            result = subprocess.run(
                cmd,
                cwd=target_path,
                capture_output=True,
                text=True,
                check=True
            )
            
            mvs_modules = set()
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        module_name = parts[0]
                        module_version = parts[1]
                        mvs_modules.add(f"{module_name}@{module_version}")
                    else:
                        mvs_modules.add(parts[0])
            
            return mvs_modules
            
        except subprocess.CalledProcessError as e:
            print(f"ERROR: Failed to get MVS selected modules: {e}")
            return set()
    
    def _get_graph_modules(self, target_path: str) -> Tuple[Dict[str, str], Dict[str, List[str]]]:
        """Get all modules and dependencies from go mod graph"""
        try:
            cmd = ["go", "mod", "graph"]
            result = subprocess.run(
                cmd,
                cwd=target_path,
                capture_output=True,
                text=True,
                check=True
            )
            
            graph_modules = {}
            graph_dependencies = {}
            
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        parent = parts[0]
                        child = parts[1]
                        
                        parent_name, parent_version = self._parse_module_version(parent)
                        child_name, child_version = self._parse_module_version(child)
                        
                        graph_modules[parent] = parent_version
                        graph_modules[child] = child_version
                        
                        if parent not in graph_dependencies:
                            graph_dependencies[parent] = []
                        graph_dependencies[parent].append(child)
            
            return graph_modules, graph_dependencies
            
        except subprocess.CalledProcessError as e:
            print(f"ERROR: Failed to get graph modules: {e}")
            return {}, {}

    def _get_deep_require_graph(self, target_path: str) -> Tuple[Dict[str, str], Dict[str, List[str]], Dict[str, List[str]]]:
        """Build a deep dependency graph by recursively parsing each module's own go.mod requires.

        This expands beyond the pruned build graph to include requires declared by each module,
        even if they are not needed for the main module's build under lazy loading.
        """
        try:
            mvs = self._get_mvs_selected_modules(target_path)
            path_to_version: Dict[str, str] = {}
            root_list_cmd = ["go", "list", "-m", "-json", "all"]
            root_list = subprocess.run(
                root_list_cmd,
                cwd=target_path,
                capture_output=True,
                text=True,
                check=True
            )
            # Parse concatenated JSON objects line by line
            buf = []
            for line in root_list.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                buf.append(line)
                if line.endswith('}'):  # naive boundary
                    try:
                        obj = json.loads("\n".join(buf))
                        buf = []
                    except Exception:
                        continue
                    p = obj.get("Path", "").strip('"').strip("'")  # Remove quotes if present
                    v = obj.get("Version", "").strip('"').strip("'")  # Remove quotes if present
                    if p:
                        path_to_version[p] = v

            # Cache for go.mod paths and parsed requires
            gomod_path_cache: Dict[Tuple[str, str], Optional[str]] = {}
            # cache stores list of (module, version, is_indirect)
            require_cache: Dict[Tuple[str, str], List[Tuple[str, str, bool]]] = {}

            def get_gomod_path(module_path: str, version: str) -> Optional[str]:
                # Strip quotes if present (fix for malformed module paths)
                clean_module_path = module_path.strip().strip('"').strip("'")
                clean_version = version.strip().strip('"').strip("'") if version else ""
                
                # Skip if module path is empty
                if not clean_module_path:
                    return None
                
                key = (module_path, version)
                if key in gomod_path_cache:
                    return gomod_path_cache[key]
                
                try:
                    # If version is empty, this is likely the main module (local project)
                    # Use the local go.mod file directly instead of downloading
                    if not clean_version:
                        local_gomod = os.path.join(target_path, "go.mod")
                        if os.path.exists(local_gomod):
                            # Check if this module is actually the main module
                            # by checking if it appears in path_to_version with empty version
                            if clean_module_path in path_to_version and path_to_version[clean_module_path] == "":
                                print(f"DEBUG: Using local go.mod for main module: {clean_module_path}")
                                gomod_path_cache[key] = local_gomod
                                return local_gomod
                        # If not main module or file doesn't exist, can't proceed
                        print(f"DEBUG: Skipping download for {module_path} (no version, not main module or go.mod not found)")
                        gomod_path_cache[key] = None
                        return None
                    
                    # For modules with version, download using go mod download
                    cmd = ["go", "mod", "download", "-json", f"{clean_module_path}@{clean_version}"]
                    
                    res = subprocess.run(
                        cmd,
                        cwd=target_path,
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    
                    # Check if stdout is empty
                    if not res.stdout or not res.stdout.strip():
                        print(f"DEBUG: Empty response from go mod download for {module_path}@{clean_version}")
                        gomod_path_cache[key] = None
                        return None
                    
                    try:
                        data = json.loads(res.stdout)
                        gomod_path_cache[key] = data.get("GoMod")
                        return gomod_path_cache[key]
                    except json.JSONDecodeError as e:
                        print(f"DEBUG: Failed to parse download json for {module_path}@{clean_version}")
                        print(f"       stdout was: {res.stdout[:300] if res.stdout else 'empty'}")
                        print(f"       JSON error: {e}")
                        gomod_path_cache[key] = None
                        return None
                except subprocess.CalledProcessError as e:
                    # More detailed error logging
                    stderr_msg = e.stderr.strip() if e.stderr else "No stderr"
                    stdout_msg = e.stdout.strip() if e.stdout else "No stdout"
                    print(f"DEBUG: go mod download failed for {module_path}@{clean_version}")
                    print(f"       Return code: {e.returncode}")
                    if stderr_msg:
                        print(f"       stderr: {stderr_msg[:200]}")  # Limit length
                    if stdout_msg:
                        print(f"       stdout: {stdout_msg[:200]}")
                    gomod_path_cache[key] = None
                    return None

            def parse_requires(module_path: str, version: str) -> List[Tuple[str, str, bool]]:
                key = (module_path, version)
                if key in require_cache:
                    return require_cache[key]
                gomod_fp = get_gomod_path(module_path, version)
                requires: List[Tuple[str, str, bool]] = []
                if not gomod_fp:
                    require_cache[key] = requires
                    return requires
                try:
                    with open(gomod_fp, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                    in_block = False
                    for raw in lines:
                        s = raw.strip()
                        if not s or s.startswith('//'):
                            continue
                        if s.startswith('require ('):
                            in_block = True
                            continue
                        if in_block and s == ')':
                            in_block = False
                            continue
                        if in_block:
                            parts = s.split()
                            if len(parts) >= 2:
                                mod = parts[0].strip('"').strip("'")  # Remove quotes
                                ver = parts[1].strip('"').strip("'")  # Remove quotes
                                is_indirect = ('//' in raw and 'indirect' in raw)
                                if ver != '':
                                    requires.append((mod, ver, is_indirect))
                            continue
                        if s.startswith('require '):
                            parts = s[len('require '):].split()
                            if len(parts) >= 2:
                                mod = parts[0].strip('"').strip("'")  # Remove quotes
                                ver = parts[1].strip('"').strip("'")  # Remove quotes
                                is_indirect = ('//' in raw and 'indirect' in raw)
                                requires.append((mod, ver, is_indirect))
                except Exception as e:
                    print(f"DEBUG: Failed to parse requires for {module_path}@{version}: {e}")
                require_cache[key] = requires
                return requires

            deep_modules: Dict[str, str] = {}
            deep_edges: Dict[str, List[str]] = {}
            deep_edges_direct_only: Dict[str, List[str]] = {}
            visiting: Set[str] = set()

            def normalize_full_name(path: str, ver: str) -> str:
                return f"{path}@{ver}" if ver else path

            def resolved_version(path: str, declared_ver: str) -> str:
                # Prefer version chosen by the main build list if present
                return path_to_version.get(path, declared_ver)

            def dfs(path: str, ver: str):
                key = normalize_full_name(path, ver)
                if key in visiting:
                    return
                visiting.add(key)
                deep_modules[key] = ver
                reqs = parse_requires(path, ver)
                if key not in deep_edges:
                    deep_edges[key] = []
                if key not in deep_edges_direct_only:
                    deep_edges_direct_only[key] = []
                for dep_path, dep_decl_ver, is_indirect in reqs:
                    dep_ver = resolved_version(dep_path, dep_decl_ver)
                    dep_key = normalize_full_name(dep_path, dep_ver)
                    deep_edges[key].append(dep_key)
                    if not is_indirect:
                        deep_edges_direct_only[key].append(dep_key)
                    dfs(dep_path, dep_ver)

            # Seed DFS with modules in the pruned build list for maximal coverage
            for p, v in path_to_version.items():
                dfs(p, v)

            return deep_modules, deep_edges, deep_edges_direct_only
        except subprocess.CalledProcessError as e:
            print(f"ERROR: Failed to build deep require graph: {e}")
            return {}, {}, {}
    
    def _parse_module_version(self, module: str) -> Tuple[str, str]:
        """Parse module name and version from 'name@version' format"""
        if '@' in module:
            parts = module.split('@', 1)
            return parts[0], parts[1]
        return module, ""
    
    def _get_direct_dependencies(self, target_path: str) -> Set[str]:
        """Get direct dependencies from go.mod file"""
        try:
            go_mod_path = os.path.join(target_path, "go.mod")
            if not os.path.exists(go_mod_path):
                return set()
            
            with open(go_mod_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            direct_deps = set()
            lines = content.split('\n')
            
            for line in lines:
                if not line.strip() or line.strip().startswith('//'):
                    continue
                
                if line.startswith('\t'):
                    parts = line.strip().split()
                    if len(parts) >= 2 and not line.strip().endswith('// indirect'):
                        module_name = parts[0]
                        module_version = parts[1]
                        direct_deps.add(f"{module_name}@{module_version}")
            
            return direct_deps
            
        except Exception as e:
            print(f"ERROR: Failed to parse go.mod file: {e}")
            return set()
    
    def _get_root_module(self, target_path: str) -> str:
        """Get root module name"""
        try:
            cmd = ["go", "list", "-m"]
            result = subprocess.run(
                cmd,
                cwd=target_path,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            print(f"ERROR: Failed to get root module: {e}")
            return "unknown"
    
    def _find_go_mod_file(self, target_path: str) -> str:
        """Find go.mod file in target path or subdirectories"""
        root_go_mod = os.path.join(target_path, "go.mod")
        if os.path.exists(root_go_mod):
            return target_path
        
        print(f"DEBUG: go.mod not found in root, scanning subdirectories...")
        
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', 'vendor', '__pycache__']]
            
            if "go.mod" in files:
                go_mod_dir = root
                print(f"DEBUG: Found go.mod in subdirectory: {go_mod_dir}")
                return go_mod_dir
        
        return None
    
    def _get_root_module_with_git_context(self, go_mod_path: str, target_path: str, git_url: str = None) -> str:
        """Get root module name with Git URL context for proper naming"""
        basic_module = self._get_root_module(go_mod_path)
        
        if not git_url:
            return basic_module
        
        from urllib.parse import urlparse
        
        try:
            parsed = urlparse(git_url.replace('.git', ''))
            if parsed.hostname == 'github.com':
                path_parts = parsed.path.strip('/').split('/')
                if len(path_parts) >= 2:
                    owner = path_parts[0]
                    repo = path_parts[1]
                    
                    import os
                    rel_path = os.path.relpath(go_mod_path, target_path)
                    
                    if rel_path == '.':
                        return f"github.com/{owner}/{repo}"
                    else:
                        return f"github.com/{owner}/{repo}/{rel_path}"
        except Exception as e:
            print(f"DEBUG: Failed to parse Git URL: {e}")
        
        return basic_module
    
    def _get_git_version(self, target_path: str) -> Optional[str]:
        """Get clean version from Git repository"""
        try:
            import subprocess
            
            result = subprocess.run(
                ["git", "describe", "--tags", "--exact-match"],
                cwd=target_path,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                return version
            
            result = subprocess.run(
                ["git", "tag", "--sort=-version:refname"],
                cwd=target_path,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                tags = result.stdout.strip().split('\n')
                for tag in tags:
                    if not any(suffix in tag.lower() for suffix in ['-test', '-rc', '-beta', '-alpha', '-dev', 'latest-release']):
                        return tag
                
                latest_tag = tags[0]
                return latest_tag
            
            result = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=target_path,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
                
        except Exception as e:
            print(f"DEBUG: Failed to get Git version: {e}")
        
        return None
