#!/usr/bin/env python3
"""
NPM Analyzer for SBOM Generator
Analyzes NPM projects and extracts package information
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
import yaml
import urllib.request
import urllib.error
from .baseAnalyzer import BaseAnalyzer, ProjectType


class NpmAnalyzer(BaseAnalyzer):
    """NPM project analyzer for SBOM generation"""
    
    def __init__(self, project_path: str):
        """
        Initialize NPM analyzer
        
        Args:
            project_path: Path to the NPM project directory
        """
        super().__init__(project_path)
        
        if not self.is_npm():
            raise ValueError(f"Not an NPM project: {project_path}")
        
        self.package_json_path = self.project_path / "package.json"
        self.package_lock_path = self.project_path / "package-lock.json"
        self.pnpm_lock_path = self.project_path / "pnpm-lock.yaml"
        
        # Detect if this is a pnpm project
        self.is_pnpm = self.pnpm_lock_path.exists()
        
        # Load package.json
        self.package_data = self._load_package_json()
        
        # For pnpm projects, use pnpm-lock.yaml; for npm, ensure package-lock.json exists
        if self.is_pnpm:
            print("Detected pnpm project (pnpm-lock.yaml found)")
            self.pnpm_lock_data = self._load_pnpm_lock()
            # Convert pnpm-lock.yaml to package-lock.json-like structure for compatibility
            self.package_lock_data = self._convert_pnpm_to_npm_format()
        else:
            # Ensure package-lock.json exists
            self._ensure_package_lock()
            # Load package-lock.json
            self.package_lock_data = self._load_package_lock()
        
        self._license_cache: Dict[str, Optional[str]] = {}
        self._package_deps_cache: Dict[str, Optional[Dict[str, str]]] = {}
    
    def _load_package_json(self) -> Dict[str, Any]:
        """Load and parse package.json"""
        try:
            with open(self.package_json_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            raise ValueError(f"Failed to load package.json: {e}")
    
    def _load_package_lock(self) -> Dict[str, Any]:
        """Load and parse package-lock.json"""
        try:
            with open(self.package_lock_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            raise ValueError(f"Failed to load package-lock.json: {e}")
    
    def _load_pnpm_lock(self) -> Dict[str, Any]:
        """Load and parse pnpm-lock.yaml"""
        try:
            with open(self.pnpm_lock_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            raise ValueError(f"Failed to load pnpm-lock.yaml: {e}")
    
    def _convert_pnpm_to_npm_format(self) -> Dict[str, Any]:
        """Convert pnpm-lock.yaml structure to package-lock.json-like format"""
        if not hasattr(self, 'pnpm_lock_data') or not self.pnpm_lock_data:
            return {}
        
        lockfile_version = self.pnpm_lock_data.get('lockfileVersion', 5)
        packages = {}
        
        # Build a mapping of package name to version from importers (actual installed versions)
        # This ensures we use the versions specified in importers, not just packages section
        importers = self.pnpm_lock_data.get('importers', {})
        root_importer = importers.get('.', {})
        version_map = {}  # package_name -> version
        
        # Collect versions from dependencies
        for dep_name, dep_info in root_importer.get('dependencies', {}).items():
            if isinstance(dep_info, dict):
                version_str = dep_info.get('version', '')
                if version_str:
                    actual_version = version_str.split('(')[0] if version_str else ''
                    if actual_version and not actual_version.startswith('link:'):
                        version_map[dep_name] = actual_version
        
        # Collect versions from devDependencies
        for dep_name, dep_info in root_importer.get('devDependencies', {}).items():
            if isinstance(dep_info, dict):
                version_str = dep_info.get('version', '')
                if version_str:
                    actual_version = version_str.split('(')[0] if version_str else ''
                    if actual_version and not actual_version.startswith('link:'):
                        version_map[dep_name] = actual_version
        
        # Collect versions from optionalDependencies
        for dep_name, dep_info in root_importer.get('optionalDependencies', {}).items():
            if isinstance(dep_info, dict):
                version_str = dep_info.get('version', '')
                if version_str:
                    actual_version = version_str.split('(')[0] if version_str else ''
                    if actual_version and not actual_version.startswith('link:'):
                        version_map[dep_name] = actual_version
        
        # Process packages from pnpm-lock.yaml
        pnpm_packages = self.pnpm_lock_data.get('packages', {})
        
        # First, add packages from version_map (direct dependencies) even if not in packages section
        # This ensures all direct dependencies are included
        for package_name, version in version_map.items():
            # Check if this package exists in packages section with the correct version
            package_found = False
            for pkg_path in pnpm_packages.keys():
                if package_name.startswith('@'):
                    # Scoped package: /@scope/package/version
                    if f'/{package_name}/{version}' in pkg_path:
                        package_found = True
                        break
                else:
                    # Regular package: /package/version
                    if f'/{package_name}/{version}' in pkg_path:
                        package_found = True
                        break
            
            # If not found in packages section, create a minimal entry
            if not package_found:
                npm_path = f"node_modules/{package_name}"
                packages[npm_path] = {
                    'name': package_name,
                    'version': version,
                    'description': '',
                    'author': '',
                    'license': '',
                    'homepage': '',
                    'repository': '',
                    'bugs': '',
                    'keywords': [],
                    'engines': {},
                    'optional': False,
                    'dev': False,
                    'peer': False,
                    'bundled': False,
                }
        
        # Process ALL packages from pnpm-lock.yaml (including indirect dependencies)
        for pkg_path, pkg_info in pnpm_packages.items():
            if not pkg_info or not isinstance(pkg_info, dict):
                continue
            
            # Extract package name and version from path
            # pnpm paths in v9+ format: @scope/package@version or package@version
            # Examples: @babel/runtime@7.28.4, prettier@3.6.2
            if pkg_path.startswith('file:'):
                continue
            
            # Remove registry prefix if present (e.g., "registry.npmjs.org/@babel/runtime@7.28.4")
            clean_path = pkg_path
            if '@' in clean_path and '/' in clean_path and not clean_path.startswith('@'):
                # Has registry prefix, remove it
                parts = clean_path.split('@', 1)
                if len(parts) > 1:
                    # Find the last @ which separates package name from version
                    clean_path = '@' + parts[1]
            
            package_name = ''
            version = ''
            
            # Parse format: @scope/package@version or package@version
            if '@' in clean_path:
                # Split by last @ to separate name and version
                last_at = clean_path.rfind('@')
                if last_at > 0:
                    package_name = clean_path[:last_at]
                    version = clean_path[last_at + 1:]
            
            # Fallback: try to get from package info
            if not package_name:
                package_name = pkg_info.get('name', '')
            if not version:
                version = pkg_info.get('version', '')
            
            if not package_name or not version:
                continue
            
            # For packages in version_map (direct dependencies), use the version from importers
            # For other packages (indirect dependencies), use version from path/info
            if package_name in version_map:
                expected_version = version_map[package_name]
                # Use the version from importers for direct dependencies
                version = expected_version
            # For packages not in version_map (indirect dependencies), keep version from path/info
            
            # Create npm-style package path
            if package_name.startswith('@'):
                npm_path = f"node_modules/{package_name}"
            else:
                npm_path = f"node_modules/{package_name}"
            
            # Convert pnpm package info to npm format
            npm_pkg_info = {
                'name': package_name,
                'version': version,
                'description': pkg_info.get('description', ''),
                'author': pkg_info.get('author', ''),
                'license': pkg_info.get('license', ''),
                'homepage': pkg_info.get('homepage', ''),
                'repository': pkg_info.get('repository', ''),
                'bugs': pkg_info.get('bugs', ''),
                'keywords': pkg_info.get('keywords', []),
                'engines': pkg_info.get('engines', {}),
                'optional': pkg_info.get('optional', False),
                'dev': pkg_info.get('dev', False),
                'peer': pkg_info.get('peer', False),
                'bundled': pkg_info.get('bundled', False),
            }
            
            # Handle resolution/integrity
            resolution = pkg_info.get('resolution', {})
            if isinstance(resolution, dict):
                npm_pkg_info['integrity'] = resolution.get('integrity', '')
                npm_pkg_info['resolved'] = resolution.get('tarball', '')
            elif isinstance(resolution, str):
                # Sometimes resolution is just a string (tarball URL)
                npm_pkg_info['resolved'] = resolution
            
            # Convert dependencies
            pnpm_deps = pkg_info.get('dependencies', {})
            if pnpm_deps:
                npm_deps = {}
                for dep_name, dep_version in pnpm_deps.items():
                    # Find the actual version from packages
                    actual_version = self._find_pnpm_package_version(dep_name, dep_version)
                    if actual_version:
                        npm_deps[dep_name] = {
                            'version': actual_version,
                            'resolved': '',
                            'integrity': ''
                        }
                if npm_deps:
                    npm_pkg_info['dependencies'] = npm_deps
            
            # Handle optionalDependencies
            pnpm_opt_deps = pkg_info.get('optionalDependencies', {})
            if pnpm_opt_deps:
                if 'dependencies' not in npm_pkg_info:
                    npm_pkg_info['dependencies'] = {}
                for dep_name, dep_version in pnpm_opt_deps.items():
                    actual_version = self._find_pnpm_package_version(dep_name, dep_version)
                    if actual_version:
                        npm_pkg_info['dependencies'][dep_name] = {
                            'version': actual_version,
                            'resolved': '',
                            'integrity': '',
                            'optional': True
                        }
            
            # Use package_key (name@version) as unique identifier to avoid duplicates
            # But for npm format compatibility, we still use npm_path as key
            # If same npm_path exists, we keep the one with matching version from version_map (direct dep)
            if npm_path in packages:
                # If this is a direct dependency (in version_map), prefer it
                if package_name in version_map:
                    packages[npm_path] = npm_pkg_info
                # Otherwise, keep existing (might be direct dependency)
            else:
                packages[npm_path] = npm_pkg_info
        
        # Create package-lock.json-like structure
        return {
            'name': self.package_data.get('name', 'unknown'),
            'version': self.package_data.get('version', '1.0.0'),
            'lockfileVersion': lockfile_version,
            'requires': True,
            'packages': packages,
            'dependencies': {}  # Will be built from packages
        }
    
    def _find_pnpm_package_version(self, package_name: str, version_spec: str) -> Optional[str]:
        """Find the actual installed version of a package from pnpm-lock.yaml
        
        Args:
            package_name: Name of the package to find
            version_spec: Version specification from dependencies field (usually already the actual version)
        
        Returns:
            Actual installed version if found, otherwise version_spec
        """
        if not hasattr(self, 'pnpm_lock_data') or not self.pnpm_lock_data:
            return version_spec
        
        packages = self.pnpm_lock_data.get('packages', {})
        
        # In pnpm-lock.yaml, dependencies field usually contains the actual version
        # First, check if version_spec matches a package in packages section
        # Format: package_name@version_spec or @scope/package_name@version_spec
        expected_paths = [
            f"{package_name}@{version_spec}",
            f"/{package_name}@{version_spec}"  # With registry prefix
        ]
        
        for expected_path in expected_paths:
            if expected_path in packages:
                return version_spec
        
        # If exact match not found, search for the package name and return first matching version
        # This handles cases where version_spec might be a range
        for pkg_path, pkg_info in packages.items():
            if not pkg_info or not isinstance(pkg_info, dict):
                continue
            
            if pkg_path.startswith('file:'):
                continue
            
            # Parse package name and version from path (format: @scope/package@version or package@version)
            clean_path = pkg_path
            if '@' in clean_path and '/' in clean_path and not clean_path.startswith('@'):
                # Has registry prefix, remove it
                parts = clean_path.split('@', 1)
                if len(parts) > 1:
                    clean_path = '@' + parts[1]
            
            found_name = ''
            found_version = ''
            
            if '@' in clean_path:
                last_at = clean_path.rfind('@')
                if last_at > 0:
                    found_name = clean_path[:last_at]
                    found_version = clean_path[last_at + 1:]
            
            if not found_name:
                found_name = pkg_info.get('name', '')
            if not found_version:
                found_version = pkg_info.get('version', '')
            
            if found_name == package_name:
                return found_version if found_version else version_spec
        
        # If not found, return version_spec (it's likely already the actual version)
        return version_spec
    
    def _fetch_package_dependencies_from_registry(self, package_name: str, version: str) -> Optional[Dict[str, str]]:
        """Fetch package dependencies from npm registry API
        
        Args:
            package_name: Name of the package
            version: Version of the package
        
        Returns:
            Dictionary of dependencies {dep_name: dep_version} or None if failed
        """
        cache_key = f"{package_name}@{version}"
        if cache_key in self._package_deps_cache:
            return self._package_deps_cache[cache_key]
        
        try:
            # Use npm registry API
            # URL format: https://registry.npmjs.org/{package_name}/{version}
            registry_url = f"https://registry.npmjs.org/{package_name}/{version}"
            
            req = urllib.request.Request(registry_url)
            req.add_header('Accept', 'application/json')
            
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                # Extract dependencies
                deps = {}
                if 'dependencies' in data:
                    deps.update(data['dependencies'])
                if 'optionalDependencies' in data:
                    deps.update(data['optionalDependencies'])
                
                self._package_deps_cache[cache_key] = deps if deps else None
                return deps if deps else None
                
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # Package not found
                self._package_deps_cache[cache_key] = None
                return None
            # Other HTTP errors - try npm view as fallback
            pass
        except Exception as e:
            # Network error or other issues - try npm view as fallback
            pass
        
        # Fallback: use npm view command
        try:
            result = subprocess.run(
                ["npm", "view", f"{package_name}@{version}", "dependencies", "--json"],
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                deps = json.loads(result.stdout.strip())
                if isinstance(deps, dict):
                    self._package_deps_cache[cache_key] = deps
                    return deps
        except Exception:
            pass
        
        self._package_deps_cache[cache_key] = None
        return None
    
    def _ensure_package_lock(self) -> None:
        """Ensure package-lock.json exists, run npm install if needed"""
        if not self.package_lock_path.exists():
            print("package-lock.json not found. Running npm install...")
            try:
                result = subprocess.run(
                    ["npm", "install"],
                    cwd=self.project_path,
                    capture_output=True,
                    text=True,
                    check=True
                )
                print("npm install completed successfully")
            except subprocess.CalledProcessError as e:
                if "link:" in e.stderr or "EUNSUPPORTEDPROTOCOL" in e.stderr:
                    print("Warning: npm install failed due to unsupported link: protocol dependencies.")
                    print("Attempting to generate package-lock.json by removing link: dependencies...")
                    try:
                        self._create_package_lock_without_link_deps()
                    except Exception as e2:
                        print(f"Warning: Could not generate package-lock.json: {e2}")
                        print("Continuing with package.json analysis only...")
                        self._create_empty_package_lock()
                else:
                    raise RuntimeError(f"npm install failed: {e.stderr}")
            except FileNotFoundError:
                raise RuntimeError("npm command not found. Please install Node.js and npm.")
    
    def _create_empty_package_lock(self) -> None:
        """Create an empty package-lock.json structure"""
        empty_lock = {
            "name": self.package_data.get("name", "unknown"),
            "version": self.package_data.get("version", "1.0.0"),
            "lockfileVersion": 3,
            "requires": True,
            "packages": {},
            "dependencies": {}
        }
        with open(self.package_lock_path, 'w', encoding='utf-8') as f:
            json.dump(empty_lock, f, indent=2)
    
    def _create_package_lock_without_link_deps(self) -> None:
        """Create package-lock.json by temporarily removing link: dependencies"""
        import shutil
        import tempfile
        
        modified_package = self.package_data.copy()
        
        if "devDependencies" in modified_package:
            modified_package["devDependencies"] = {
                k: v for k, v in modified_package["devDependencies"].items()
                if not (isinstance(v, str) and v.startswith("link:"))
            }
        
        backup_file = self.package_json_path.with_suffix('.json.backup')
        shutil.copy(self.package_json_path, backup_file)
        
        try:
            with open(self.package_json_path, 'w', encoding='utf-8') as f:
                json.dump(modified_package, f, indent=2)
            
            result = subprocess.run(
                ["npm", "install", "--package-lock-only"],
                cwd=self.project_path,
                capture_output=True,
                text=True,
                check=True
            )
            print("package-lock.json generated successfully (without link: dependencies)")
        finally:
            if backup_file.exists():
                shutil.copy(backup_file, self.package_json_path)
                backup_file.unlink()
    
    def _ensure_node_modules(self) -> None:
        node_modules = self.project_path / "node_modules"
        if node_modules.exists():
            return
        
        if self.is_pnpm:
            print("node_modules not found, running pnpm install --ignore-scripts...")
            try:
                subprocess.run(
                    ["pnpm", "install", "--ignore-scripts", "--no-frozen-lockfile"],
                    cwd=self.project_path,
                    check=True,
                    capture_output=True,
                    text=True
                )
                print("pnpm install completed successfully")
            except subprocess.CalledProcessError as e:
                print(f"Warning: pnpm install failed while preparing licenses: {e.stderr.strip() if e.stderr else e}")
            except FileNotFoundError:
                print("Warning: pnpm command not found. Skipping node_modules installation.")
        else:
            print("node_modules not found, running npm install --ignore-scripts...")
            try:
                subprocess.run(
                    ["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund"],
                    cwd=self.project_path,
                    check=True,
                    capture_output=True,
                    text=True
                )
                print("npm install completed successfully")
            except subprocess.CalledProcessError as e:
                print(f"Warning: npm install failed while preparing licenses: {e.stderr.strip() if e.stderr else e}")

    def analyze(self) -> Dict[str, Any]:
        """
        Analyze NPM project and extract package information
        
        Returns:
            Dictionary containing analysis results
        """
        root_package = self._extract_root_package()
        
        self._ensure_node_modules()

        all_packages = self._extract_all_packages()
        self.all_packages = all_packages  
        
        # Build dependency graph
        dependencies = self._build_dependency_graph()
        
        # Identify direct dependencies
        direct_deps = self._identify_direct_dependencies()
        
        # Add main package dependencies to the graph
        main_name = root_package.get("name", "")
        main_version = root_package.get("version", "")
        main_key = f"{main_name}@{main_version}"
        dependencies[main_key] = direct_deps
        
        # Mark direct dependencies in packages
        for package in all_packages:
            package_name = package.get("name", "")
            package_version = package.get("version", "")
            package_key = f"{package_name}@{package_version}"
            
            # Ensure metadata exists
            if "metadata" not in package:
                package["metadata"] = {}
            
            if package_key in direct_deps:
                package["metadata"]["is_direct"] = True
            else:
                package["metadata"]["is_direct"] = False
        
        return {
            "root_package": root_package,
            "packages": all_packages,
            "all_packages": all_packages,
            "dependencies": dependencies,
            "direct_dependencies": direct_deps,
            "total_packages": len(all_packages),
            "direct_deps_count": len(direct_deps),
            "project_info": {
                "name": root_package.get("name", "unknown"),
                "version": root_package.get("version", "0.0.0")
            }
        }
    
    def _extract_root_package(self) -> Dict[str, Any]:
        """Extract root package information"""
        return {
            "name": self.package_data.get("name", "unknown"),
            "version": self.package_data.get("version", "0.0.0"),
            "description": self.package_data.get("description", ""),
            "author": self.package_data.get("author", ""),
            "license": self.package_data.get("license", ""),
            "homepage": self.package_data.get("homepage", ""),
            "repository": self.package_data.get("repository", ""),
            "bugs": self.package_data.get("bugs", ""),
            "keywords": self.package_data.get("keywords", []),
            "engines": self.package_data.get("engines", {}),
            "type": "application"  
        }
    
    def _extract_all_packages(self) -> List[Dict[str, Any]]:
        """Extract all packages from package-lock.json"""
        packages = []
        
        # Add root package
        root_package = self._extract_root_package()
        packages.append(root_package)
        
        # Extract packages from package-lock.json
        has_lockfile_packages = False
        if "packages" in self.package_lock_data and len(self.package_lock_data["packages"]) > 1:  # More than just root package
            for package_path, package_info in self.package_lock_data["packages"].items():
                if package_path == "":  
                    continue
                
                package = self._parse_package_info(package_path, package_info)
                if package:
                    packages.append(package)
                    has_lockfile_packages = True
        
        # If package-lock.json is empty or invalid, extract from package.json
        if not has_lockfile_packages:
            packages.extend(self._extract_packages_from_package_json())
        
        return packages
    
    def _extract_packages_from_package_json(self) -> List[Dict[str, Any]]:
        """Extract packages from package.json when package-lock.json is unavailable"""
        packages = []
        
        # Get all dependency types
        dep_types = ["dependencies", "devDependencies", "optionalDependencies"]
        
        for dep_type in dep_types:
            if dep_type in self.package_data:
                for dep_name, dep_version in self.package_data[dep_type].items():
                    # Skip link: protocol dependencies (workspace/local dependencies)
                    if isinstance(dep_version, str) and dep_version.startswith("link:"):
                        continue
                    
                    # Clean version range
                    clean_version = self._clean_version_range(dep_version)
                    
                    # Create package info
                    package = {
                        "name": dep_name,
                        "version": clean_version,
                        "type": "library",
                        "metadata": {
                            "description": "",
                            "dependency_type": dep_type,
                            "is_direct": True,
                            "dev": dep_type == "devDependencies",
                            "optional": dep_type == "optionalDependencies"
                        }
                    }
                    packages.append(package)
        
        return packages
    
    def _extract_declared_dependencies(self) -> List[Dict[str, Any]]:
        """Extract declared dependencies from package.json that might not be installed"""
        return []
    
    def _extract_package_lock_peer_dependencies(self) -> List[Dict[str, Any]]:
        """Extract peerDependencies from package-lock.json that might not be installed"""
        return []
    
    def _parse_package_info(self, package_path: str, package_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse individual package information"""
        if not package_info:
            return None
        
        # Extract name and version
        name = package_info.get("name", "")
        version = package_info.get("version", "")
        
        # For packages without name, try to extract from package_path
        if not name and package_path and package_path != "":
            # Extract package name from path (e.g., "node_modules/express" -> "express")
            # Handle scoped packages (e.g., "node_modules/@scope/package" -> "@scope/package")
            path_parts = package_path.split("/")
            if len(path_parts) > 1 and path_parts[-2] == "node_modules":
                name = path_parts[-1]
            elif len(path_parts) > 2 and path_parts[-3] == "node_modules" and path_parts[-2].startswith("@"):
                # Handle scoped packages: "node_modules/@scope/package" -> "@scope/package"
                name = f"{path_parts[-2]}/{path_parts[-1]}"
        
        if not name or not version:
            return None
        
        # Determine package type
        package_type = "library"
        if "bin" in package_info:
            package_type = "application"
        
        # Extract metadata
        metadata = {
            "description": package_info.get("description", ""),
            "author": package_info.get("author", ""),
            "license": package_info.get("license", ""),
            "homepage": package_info.get("homepage", ""),
            "repository": package_info.get("repository", ""),
            "bugs": package_info.get("bugs", ""),
            "keywords": package_info.get("keywords", []),
            "engines": package_info.get("engines", {}),
            "optional": package_info.get("optional", False),
            "dev": package_info.get("dev", False),
            "peer": package_info.get("peer", False),
            "bundled": package_info.get("bundled", False),
            "integrity": package_info.get("integrity", ""),
            "resolved": package_info.get("resolved", ""),
            "package_path": package_path
        }

        license_id = metadata.get("license") or self._resolve_package_license(package_path, name, version, package_info)
        if license_id:
            metadata["license"] = license_id

        return {
            "name": name,
            "version": version,
            "type": package_type,
            "package_path": package_path,  # Add package path for npm-specific info
            "metadata": metadata
        }
    
    def _resolve_package_license(self, package_path: str, package_name: str, version: str, package_info: Dict[str, Any]) -> Optional[str]:
        cache_key = f"{package_path}|{package_name}@{version}"
        if cache_key in self._license_cache:
            return self._license_cache[cache_key]

        license_field = package_info.get('license')
        license_id = self._normalize_license_value(license_field)
        if not license_id:
            license_id = self._extract_license_from_package_json(package_path)
        if not license_id:
            license_id = self._fetch_license_from_registry(package_name, version)

        self._license_cache[cache_key] = license_id
        return license_id

    def _fetch_license_from_registry(self, package_name: str, version: str) -> Optional[str]:
        if not package_name or not version:
            return None
        cache_key = f"registry|{package_name}@{version}"
        if cache_key in self._license_cache:
            return self._license_cache[cache_key]
        try:
            result = subprocess.run(
                ["npm", "view", f"{package_name}@{version}", "license", "--json"],
                cwd=self.project_path,
                capture_output=True,
                text=True,
                check=True
            )
            output = result.stdout.strip()
            if not output:
                self._license_cache[cache_key] = None
                return None
            try:
                value = json.loads(output)
            except json.JSONDecodeError:
                value = output
            license_id = self._normalize_license_value(value)
        except subprocess.CalledProcessError as e:
            err = e.stderr.strip() if e.stderr else str(e)
            print(f"Warning: npm view failed for {package_name}@{version}: {err}")
            license_id = None
        self._license_cache[cache_key] = license_id
        return license_id

    def _extract_license_from_package_json(self, package_path: str) -> Optional[str]:
        if not package_path:
            return None
        full_path = self.project_path / Path(package_path)
        if not full_path.exists():
            # handle paths missing node_modules prefix
            full_path = (self.project_path / 'node_modules' / Path(package_path)).resolve()
            if not full_path.exists():
                return None
        package_json_path = full_path / 'package.json'
        if not package_json_path.exists():
            return None
        try:
            with package_json_path.open('r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception:
            return None

        license_id = self._normalize_license_value(data.get('license'))
        if license_id:
            return license_id

        licenses_field = data.get('licenses')
        if isinstance(licenses_field, list):
            for entry in licenses_field:
                license_id = self._normalize_license_value(entry)
                if license_id:
                    return license_id
        elif isinstance(licenses_field, dict):
            license_id = self._normalize_license_value(licenses_field)
            if license_id:
                return license_id

        return None

    def _normalize_license_value(self, value: Any) -> Optional[str]:
        if isinstance(value, str):
            value = value.strip()
            return value if value else None
        if isinstance(value, dict):
            for key in ('type', 'name', 'id'):
                if key in value and isinstance(value[key], str) and value[key].strip():
                    return value[key].strip()
        if isinstance(value, list):
            for item in value:
                normalized = self._normalize_license_value(item)
                if normalized:
                    return normalized
        return None

    def _build_dependency_graph(self) -> Dict[str, List[str]]:
        """Build dependency graph from package-lock.json or pnpm-lock.yaml"""
        dependencies = {}
        
        # For pnpm projects, try to read dependencies from pnpm-lock.yaml first
        # If not available, fall back to node_modules package.json files
        if self.is_pnpm and hasattr(self, 'pnpm_lock_data') and self.pnpm_lock_data:
            pnpm_packages = self.pnpm_lock_data.get('packages', {})
            
            # First, try to get dependencies from pnpm-lock.yaml packages section
            for pkg_path, pkg_info in pnpm_packages.items():
                if not pkg_info or not isinstance(pkg_info, dict):
                    continue
                
                if pkg_path.startswith('file:'):
                    continue
                
                # Parse package name and version from path
                clean_path = pkg_path
                if '@' in clean_path and '/' in clean_path and not clean_path.startswith('@'):
                    parts = clean_path.split('@', 1)
                    if len(parts) > 1:
                        clean_path = '@' + parts[1]
                
                package_name = ''
                version = ''
                
                if '@' in clean_path:
                    last_at = clean_path.rfind('@')
                    if last_at > 0:
                        package_name = clean_path[:last_at]
                        version = clean_path[last_at + 1:]
                
                if not package_name or not version:
                    package_name = pkg_info.get('name', '')
                    version = pkg_info.get('version', '')
                
                if not package_name or not version:
                    continue
                
                package_key = f"{package_name}@{version}"
                package_deps = []
                
                # Get dependencies from pnpm package info (if available in lockfile)
                pnpm_deps = pkg_info.get('dependencies', {})
                if pnpm_deps:
                    for dep_name, dep_version_spec in pnpm_deps.items():
                        # Find actual version from packages
                        actual_version = self._find_pnpm_package_version(dep_name, dep_version_spec)
                        if actual_version:
                            package_deps.append(f"{dep_name}@{actual_version}")
                
                # If no dependencies in lockfile, try node_modules package.json
                if not package_deps:
                    npm_path = f"node_modules/{package_name}"
                    pkg_json_path = self.project_path / npm_path / "package.json"
                    if pkg_json_path.exists():
                        try:
                            with open(pkg_json_path, 'r', encoding='utf-8') as f:
                                pkg_json = json.load(f)
                            
                            pkg_deps = pkg_json.get('dependencies', {})
                            for dep_name, dep_version_spec in pkg_deps.items():
                                actual_version = self._find_pnpm_package_version(dep_name, dep_version_spec)
                                if not actual_version:
                                    actual_version = self._find_actual_version(dep_name)
                                if actual_version:
                                    package_deps.append(f"{dep_name}@{actual_version}")
                            
                            pkg_opt_deps = pkg_json.get('optionalDependencies', {})
                            for opt_name, opt_version_spec in pkg_opt_deps.items():
                                actual_version = self._find_pnpm_package_version(opt_name, opt_version_spec)
                                if not actual_version:
                                    actual_version = self._find_actual_version(opt_name)
                                if actual_version:
                                    package_deps.append(f"{opt_name}@{actual_version}")
                        except Exception:
                            pass
                
                # If still no dependencies and node_modules doesn't exist, try npm registry
                if not package_deps:
                    registry_deps = self._fetch_package_dependencies_from_registry(package_name, version)
                    if registry_deps:
                        for dep_name, dep_version_spec in registry_deps.items():
                            # Find actual installed version from pnpm packages
                            actual_version = self._find_pnpm_package_version(dep_name, dep_version_spec)
                            if actual_version:
                                package_deps.append(f"{dep_name}@{actual_version}")
                
                if package_deps:
                    dependencies[package_key] = package_deps
        
        # For npm projects, use package-lock.json
        elif "packages" in self.package_lock_data:
            for package_path, package_info in self.package_lock_data["packages"].items():
                if package_path == "":  # Skip root package
                    continue
                
                # Extract package name (handle scoped packages)
                package_name = package_info.get("name", "")
                if not package_name:
                    # Extract from path for packages without name field
                    if package_path.startswith("node_modules/"):
                        path_parts = package_path.split("/")
                        if len(path_parts) > 1 and path_parts[-2] == "node_modules":
                            package_name = path_parts[-1]
                        elif len(path_parts) > 2 and path_parts[-3] == "node_modules" and path_parts[-2].startswith("@"):
                            package_name = f"{path_parts[-2]}/{path_parts[-1]}"
                
                if not package_name:
                    continue
                
                package_version = package_info.get("version", "")
                package_key = f"{package_name}@{package_version}"
                
                # Get dependencies for this package
                package_deps = []
                
                # Handle regular dependencies
                if "dependencies" in package_info:
                    for dep_name, dep_info in package_info["dependencies"].items():
                        # Handle both dict format (npm) and string format
                        if isinstance(dep_info, dict):
                            # npm format: {version: "...", resolved: "...", integrity: "..."}
                            actual_version = dep_info.get("version", "")
                        else:
                            # Find the actual installed version of this dependency
                            actual_version = self._find_actual_version(dep_name)
                        
                        if actual_version:
                            package_deps.append(f"{dep_name}@{actual_version}")
                
                # Handle optionalDependencies
                if "optionalDependencies" in package_info:
                    for opt_name, opt_info in package_info["optionalDependencies"].items():
                        if isinstance(opt_info, dict):
                            actual_version = opt_info.get("version", "")
                        else:
                            actual_version = self._find_actual_version(opt_name)
                        
                        if actual_version:
                            package_deps.append(f"{opt_name}@{actual_version}")
                            # Mark as optionalDependency in metadata
                            for pkg in self.all_packages:
                                if pkg.get("name") == opt_name and pkg.get("version") == actual_version:
                                    if "metadata" not in pkg:
                                        pkg["metadata"] = {}
                                    pkg["metadata"]["dependency_type"] = "optionalDependencies"
                                    pkg["metadata"]["is_optional"] = True
                
                if package_deps:
                    dependencies[package_key] = package_deps
        
        return dependencies
    
    def _identify_direct_dependencies(self) -> List[str]:
        """Identify direct dependencies from package.json or pnpm-lock.yaml"""
        direct_deps = []
        
        # For pnpm projects, use pnpm-lock.yaml's importers section
        if self.is_pnpm and hasattr(self, 'pnpm_lock_data') and self.pnpm_lock_data:
            # pnpm-lock.yaml structure: importers['.'] contains root project dependencies
            importers = self.pnpm_lock_data.get('importers', {})
            root_importer = importers.get('.', {})
            
            # Get dependencies from root importer
            pnpm_deps = root_importer.get('dependencies', {})
            pnpm_dev_deps = root_importer.get('devDependencies', {})
            pnpm_opt_deps = root_importer.get('optionalDependencies', {})
            
            # Process regular dependencies
            # In pnpm-lock.yaml, each dependency has a 'version' field with the actual version
            for dep_name, dep_info in pnpm_deps.items():
                if isinstance(dep_info, dict):
                    # Extract version from the dependency info
                    # Version format can be like "1.0.0" or "1.0.0(peer1@1.0.0)(peer2@2.0.0)"
                    version_str = dep_info.get('version', '')
                    # Extract just the version part (before any parentheses)
                    actual_version = version_str.split('(')[0] if version_str else ''
                    if actual_version and not actual_version.startswith('link:'):
                        direct_deps.append(f"{dep_name}@{actual_version}")
                elif isinstance(dep_info, str):
                    # Sometimes it's just a version string
                    if not dep_info.startswith('link:'):
                        direct_deps.append(f"{dep_name}@{dep_info}")
            
            # Process devDependencies
            for dep_name, dep_info in pnpm_dev_deps.items():
                if isinstance(dep_info, dict):
                    version_str = dep_info.get('version', '')
                    actual_version = version_str.split('(')[0] if version_str else ''
                    if actual_version and not actual_version.startswith('link:'):
                        direct_deps.append(f"{dep_name}@{actual_version}")
                elif isinstance(dep_info, str):
                    if not dep_info.startswith('link:'):
                        direct_deps.append(f"{dep_name}@{dep_info}")
            
            # Process optionalDependencies
            for dep_name, dep_info in pnpm_opt_deps.items():
                if isinstance(dep_info, dict):
                    version_str = dep_info.get('version', '')
                    actual_version = version_str.split('(')[0] if version_str else ''
                    if actual_version and not actual_version.startswith('link:'):
                        direct_deps.append(f"{dep_name}@{actual_version}")
                elif isinstance(dep_info, str):
                    if not dep_info.startswith('link:'):
                        direct_deps.append(f"{dep_name}@{dep_info}")
        else:
            # For npm projects, use package.json
            dep_types = [
                "dependencies",
                "devDependencies", 
                "optionalDependencies"
            ]
            
            for dep_type in dep_types:
                if dep_type in self.package_data:
                    for dep_name, dep_version in self.package_data[dep_type].items():
                        # For optionalDependencies, check if it's actually installed
                        if dep_type == "optionalDependencies":
                            actual_version = self._find_actual_version(dep_name)
                            if actual_version:
                                direct_deps.append(f"{dep_name}@{actual_version}")
                        else:
                            # Remove version range prefixes (^, ~, >=, etc.)
                            clean_version = self._clean_version_range(dep_version)
                            direct_deps.append(f"{dep_name}@{clean_version}")
        
        return direct_deps
    
    def _clean_version_range(self, version: str) -> str:
        """Clean version range to get exact version"""
        if not version:
            return version
        
        # Remove common version range prefixes
        version = version.lstrip('^~>=<')
        
        # If it's a range like ">=1.0.0 <2.0.0", take the first part
        if ' ' in version:
            version = version.split(' ')[0]
        
        return version
    
    def _find_actual_version(self, package_name: str) -> str:
        """Find the actual installed version of a package"""
        if "packages" not in self.package_lock_data:
            return ""
        
        # Look for the package in node_modules
        for path, info in self.package_lock_data["packages"].items():
            # Exact match
            if path == f"node_modules/{package_name}":
                return info.get("version", "")
            # Scoped package match (e.g., @types/express)
            elif path.startswith(f"node_modules/{package_name}/"):
                return info.get("version", "")
            # Handle scoped packages differently
            elif package_name.startswith("@") and path == f"node_modules/{package_name}":
                return info.get("version", "")
        
        return ""
    
    def get_dependency_types(self) -> Dict[str, List[str]]:
        """Get dependencies categorized by type"""
        dep_types = {
            "dependencies": [],
            "devDependencies": [],
            "peerDependencies": [],
            "optionalDependencies": []
        }
        
        for dep_type in dep_types.keys():
            if dep_type in self.package_data:
                for dep_name, dep_version in self.package_data[dep_type].items():
                    dep_types[dep_type].append(f"{dep_name}@{dep_version}")
        
        return dep_types
    
    def get_package_summary(self) -> Dict[str, Any]:
        """Get summary of package analysis"""
        analysis = self.analyze()
        
        return {
            "project_name": analysis["root_package"]["name"],
            "project_version": analysis["root_package"]["version"],
            "total_packages": analysis["total_packages"],
            "direct_dependencies": analysis["direct_deps_count"],
            "dependency_types": self.get_dependency_types(),
            "has_dev_dependencies": len(self.package_data.get("devDependencies", {})) > 0,
            "has_peer_dependencies": len(self.package_data.get("peerDependencies", {})) > 0,
            "has_optional_dependencies": len(self.package_data.get("optionalDependencies", {})) > 0
        }
