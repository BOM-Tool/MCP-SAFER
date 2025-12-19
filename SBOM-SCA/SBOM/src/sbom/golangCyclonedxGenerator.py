#!/usr/bin/env python3
"""
CycloneDX SBOM Generator
Generates CycloneDX format SBOM from Go module analysis using schema validation
"""

import json
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from pathlib import Path
import jsonschema


class CycloneDXGenerator:
    """CycloneDX SBOM Generator with schema validation"""
    
    def __init__(self, version: str = "1.6", tool_info: Optional[Dict] = None):
        self.version = version
        self.schema_url = f"http://cyclonedx.org/schema/bom-{version}.schema.json"
        self.schema_path = self._get_schema_path()
        self.schema = self._load_schema()
        
        # Tool information (configurable, defaults provided)
        self.tool_info = tool_info or {
            "vendor": "Bomtori",
            "name": "SBOMgenerator",
            "version": "1.0.0"
        }
        
        # Extract component types from schema
        self.component_types = self._extract_component_types()
    
    def _get_schema_path(self) -> Path:
        """Get path to CycloneDX schema file"""
        schema_path = Path(__file__).parent.parent.parent / "schema" / "cyclonedx" / "bom-1.6.json"
        if not schema_path.exists():
            raise FileNotFoundError(f"CycloneDX schema not found: {schema_path}")
        return schema_path
    
    def _load_schema(self) -> Dict:
        """Load CycloneDX schema from file"""
        with open(self.schema_path, 'r', encoding='utf-8') as f:
            schema = json.load(f)
        return schema
    
    def _extract_component_types(self) -> List[str]:
        """Extract component types from CycloneDX schema"""
        component_def = self.schema.get("definitions", {}).get("component", {})
        type_prop = component_def.get("properties", {}).get("type", {})
        return type_prop.get("enum", ["application", "framework", "library", "container", "operating-system", "device", "firmware", "file"])
    
    
    def generate_sbom(self, analysis_result: Dict, source_dir: str, author_info: Optional[Dict] = None, git_url: Optional[str] = None, project_type: str = "golang") -> Dict:
        """
        Generate CycloneDX SBOM from analysis result
        
        Args:
            analysis_result: Analysis result from Go analyzer
            source_dir: Source directory path
            author_info: Author information (optional)
            
        Returns:
            CycloneDX SBOM dictionary conforming to schema
        """
        source_path = Path(source_dir)
        
        # Get actual Go module name and version from analysis result
        root_module = analysis_result.get("root_module", source_path.name)
        root_version = analysis_result.get("root_version", "")
        
        # Generate unique BOM serial number
        serial_number = self._generate_serial_number()
        
        # Create all components including main module (no exclusion)
        components = self._create_components(analysis_result["packages"], None, project_type)
        
        # Remove duplicate components based on bom-ref
        seen_refs = set()
        unique_components = []
        for component in components:
            bom_ref = component.get("bom-ref")
            if bom_ref not in seen_refs:
                seen_refs.add(bom_ref)
                unique_components.append(component)
        components = unique_components
        
        # Find main component by root_module name (not just components[0])
        main_component = None
        if root_module:
            for component in components:
                if component.get("name") == root_module:
                    main_component = component
                    break
        # Fallback to first component if main not found
        if not main_component and components:
            main_component = components[0]
        # Prefer direct-only expanded dependencies if available, then expanded, then graph
        deps_source = (
            analysis_result.get("expanded_dependencies_direct_only") or
            analysis_result.get("expanded_dependencies") or
            analysis_result["dependencies"]
        )
        dependencies = self._create_dependencies(main_component, components, deps_source, analysis_result)
        
        # Create metadata with all required fields
        metadata = self._create_metadata(author_info)
        
        # Build complete SBOM conforming to CycloneDX schema
        sbom = {
            "$schema": self.schema_url,
            "bomFormat": "CycloneDX",
            "specVersion": self.version,
            "serialNumber": serial_number,
            "version": 1,
            "metadata": metadata,
            "components": components,
            "dependencies": dependencies
        }
        
        # Validate SBOM against schema
        self._validate_sbom(sbom)
        
        return sbom
    
    def _validate_sbom(self, sbom: Dict) -> None:
        """Validate SBOM against CycloneDX schema"""
        try:
            jsonschema.validate(sbom, self.schema)
            print("SBOM validation successful - conforms to CycloneDX schema")
        except jsonschema.exceptions._WrappedReferencingError as e:
            print(f"SBOM validation warning: failed to resolve reference ({e}). Proceeding without strict validation.")
        except jsonschema.ValidationError as e:
            print(f"SBOM validation failed: {e.message}")
            print(f"Path: {' -> '.join(str(p) for p in e.absolute_path)}")
            raise ValueError(f"Generated SBOM does not conform to CycloneDX schema: {e.message}")
        except jsonschema.SchemaError as e:
            print(f"Schema error: {e.message}")
            raise ValueError(f"Schema validation error: {e.message}")
    
    def _generate_serial_number(self) -> str:
        """Generate RFC-4122 compliant serial number"""
        unique_id = str(uuid.uuid4())
        return f"urn:uuid:{unique_id}"
    
    def _create_metadata(self, author_info: Optional[Dict] = None) -> Dict:
        """Create metadata with all required fields"""
        metadata = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [self.tool_info]
        }
        
        # Add author information if provided
        if author_info:
            metadata["authors"] = [author_info]
        
        return metadata
    
    
    def _create_components(self, packages: List[Dict], root_module: str = None, project_type: str = "golang") -> List[Dict]:
        """Create components from packages with supplier information and MVS metadata"""
        components = []
        
        for package in packages:
            name = package["name"]
            version = package["version"]
            metadata = package.get("metadata", {})
            
            # Skip root module to avoid duplication with metadata.component
            if root_module and name == root_module:
                continue
            
            # Debug: print first few packages
            if len(components) < 3:
                print(f"DEBUG: Processing package: {name}@{version}")
            
            # Generate PURL based on project type
            if project_type == "npm":
                # Handle npm scoped packages (e.g., @scope/package -> %40scope%2Fpackage)
                if name.startswith('@'):
                    # For scoped packages, encode the @ and / in the PURL
                    encoded_name = name.replace('@', '%40').replace('/', '%2F')
                    if version and version != "":
                        purl = f"pkg:npm/{encoded_name}@{version}"
                    else:
                        purl = f"pkg:npm/{encoded_name}"
                else:
                    if version and version != "":
                        purl = f"pkg:npm/{name}@{version}"
                    else:
                        purl = f"pkg:npm/{name}"
            else:  # golang
                if version and version != "":
                    purl = f"pkg:golang/{name}@{version}"
                else:
                    purl = f"pkg:golang/{name}"
            
            # Generate unique BOM reference with package path for npm
            if project_type == "npm" and "package_path" in package:
                package_path = package.get("package_path", "")
                hash_input = f"{name}@{version}#{package_path}"
            else:
                hash_input = name + str(version)
            
            # For npm scoped packages, encode @ in bom-ref but keep name as-is
            if project_type == "npm" and name.startswith('@'):
                encoded_name_for_bom_ref = name.replace('@', '%40')
                bom_ref = f"pkg:npm/{encoded_name_for_bom_ref}@{version}?package-id={self._generate_hash(hash_input)}"
            else:
                bom_ref = f"{purl}?package-id={self._generate_hash(hash_input)}"
            
            
            license_id = package.get("metadata", {}).get("license") or package.get("license")
            # Create component with fields in specified order
            component = {
                "bom-ref": bom_ref,
                "type": "library",  # Required field - using schema-defined type
                "name": name,       # Required field
                "version": version if version and version != "" else None,
                "cpe": self._generate_cpe(name, version, project_type),
                "purl": purl
            }
            if license_id:
                component["licenses"] = [{
                    "license": {
                        "id": license_id
                    }
                }]
            
            # Add npm-specific properties
            if project_type == "npm" and "package_path" in package:
                package_path = package.get("package_path", "")
                if package_path:
                    component["properties"] = [
                        {
                            "name": "npm:packagePath",
                            "value": package_path
                        }
                    ]
            
            # Remove None values to keep JSON clean
            component = {k: v for k, v in component.items() if v is not None}
            
            components.append(component)
        
        return components
    
    def _create_dependencies(self, main_component: Dict, components: List[Dict], 
                           dependencies: Dict, analysis_result: Dict) -> List[Dict]:
        """Create dependencies section conforming to schema"""
        deps = []
        
        # Create a map to track dependencies for each component
        component_deps_map = {}
        
        # Add dependencies for main component - only DIRECT dependencies (12개)
        main_component_deps = []
        
        # Get direct dependencies from analysis_result (only those marked as is_direct=True)
        packages = analysis_result.get("packages", [])
        for package in packages:
            metadata = package.get("metadata", {})
            if metadata.get("is_direct", False):
                name = package.get("name", "")
                version = package.get("version", "")
                
                # Find corresponding component and add to dependencies
                for component in components:
                    if (component.get("name") == name and 
                        component.get("version") == version):
                        main_component_deps.append(component["bom-ref"])
                        break
        
        if main_component_deps:
            component_deps_map[main_component["bom-ref"]] = main_component_deps
        
        # Add dependencies for each component
        for component in components:
            component_name = component["name"]
            component_version = component.get("version", "")
            component_full_name = f"{component_name}@{component_version}" if component_version else component_name
            
            # Try name@version format first (most specific)
            # For expanded_dependencies (deep_edges), keys are always "path@version" format
            # Only use exact match to avoid false positives
            dep_key = None
            if component_full_name in dependencies:
                dep_key = component_full_name
            # Skip name-only match to prevent false positives
            # expanded_dependencies uses "path@version" format, so name-only match would only work
            # for go mod graph, which we're trying to avoid using when expanded_dependencies is available
            
            if dep_key and dep_key in dependencies:
                component_deps = []
                deps_list = dependencies[dep_key]
                
                # Only process if we have actual dependencies (not empty list)
                if deps_list:
                    for dep_name in deps_list:
                        # dep_name format can be "path@version" or just "path"
                        # Find the component by matching both formats
                        for other_component in components:
                            other_name = other_component["name"]
                            other_version = other_component.get("version", "")
                            other_full_name = f"{other_name}@{other_version}" if other_version else other_name
                            
                            # Match by full name (path@version) or just name (path)
                            if dep_name == other_full_name or dep_name == other_name:
                                # Only include direct dependencies for the main component
                                if component == main_component:
                                    # Check if this is a direct dependency
                                    is_direct = other_component.get("metadata", {}).get("is_direct", False)
                                    if is_direct:
                                        component_deps.append(other_component["bom-ref"])
                                else:
                                    # For other components, include all dependencies
                                    component_deps.append(other_component["bom-ref"])
                                break
                
                if component_deps:
                    component_deps_map[component["bom-ref"]] = component_deps
        
        # Convert map to list format
        for ref, depends_on in component_deps_map.items():
            deps.append({
                "ref": ref,
                "dependsOn": depends_on
            })
        
        return deps
    
    def _generate_cpe(self, name: str, version: str, project_type: str = "golang") -> Optional[str]:
        if not name:
            return None
        
        if project_type == "npm":
            vendor, product = self._candidate_vendor_product_for_npm(name)
        else:
            vendor = self._candidate_vendor_for_go(name)
            product = self._candidate_product_for_go(name)
        
        if not product or not vendor:
            return None
        
        # Clean up version
        clean_version = version.replace("v", "") if version else "*"
        
        return f"cpe:2.3:a:{vendor}:{product}:{clean_version}:*:*:*:*:*:*:*"
    
    def _candidate_product_for_go(self, name: str) -> str:
        from urllib.parse import urlparse
        
        # Add scheme for proper URL parsing
        url_str = "http://" + name
        try:
            parsed = urlparse(url_str)
        except:
            return ""
        
        clean_path = parsed.path.strip('/')
        path_elements = clean_path.split('/')
        
        # Handle special cases
        if parsed.hostname == "golang.org" or parsed.hostname == "gopkg.in":
            return clean_path
        elif parsed.hostname == "google.golang.org":
            return path_elements[0] if path_elements else ""
        
        # For other cases, return path elements after the first one
        if len(path_elements) < 2:
            return ""
        
        return "/".join(path_elements[1:])
    
    def _candidate_vendor_for_go(self, name: str) -> str:
        from urllib.parse import urlparse
        
        # Add scheme for proper URL parsing
        url_str = "http://" + name
        try:
            parsed = urlparse(url_str)
        except:
            return "unknown"
        
        clean_path = parsed.path.strip('/')
        path_elements = clean_path.split('/')
        
        # Handle special cases
        if parsed.hostname == "google.golang.org":
            return "google"
        elif parsed.hostname == "golang.org":
            return "golang"
        elif parsed.hostname == "gopkg.in":
            return ""
        
        # For other cases, return the first path element
        if len(path_elements) < 2:
            return "unknown"
        
        return path_elements[0]
    
    def _candidate_vendor_product_for_npm(self, name: str) -> tuple[str, str]:
        """Extract vendor and product from npm package name"""
        if not name:
            return "", ""
        
        # Handle scoped packages (@scope/package)
        if name.startswith('@'):
            parts = name.split('/')
            if len(parts) >= 2:
                vendor = parts[0][1:]  # Remove @ prefix
                product = parts[1]
                return vendor, product
            else:
                return "", ""
        
        # For non-scoped packages, use the package name as both vendor and product
        # or try to extract vendor from common patterns
        if '/' in name:
            parts = name.split('/')
            if len(parts) >= 2:
                vendor = parts[0]
                product = parts[1]
                return vendor, product
        
        # Default: use package name as product, "npm" as vendor
        return "npm", name
    
    def _generate_hash(self, input_string: str) -> str:
        """Generate 16-character hash for unique package identification"""
        import hashlib
        
        # Use SHA-256 and take first 16 characters for uniqueness
        hash_object = hashlib.sha256(input_string.encode('utf-8'))
        hex_dig = hash_object.hexdigest()
        
        # Return first 16 characters of SHA-256 hash
        return hex_dig[:16]
    
    def _parse_git_url(self, git_url: str) -> Dict[str, str]:
        """Parse Git URL to extract repository information"""
        if not git_url:
            return {"name": "unknown", "full_path": ""}
        
        # Remove .git suffix if present
        clean_url = git_url.replace('.git', '')
        
        # Extract repository name
        repo_name = clean_url.split('/')[-1]
        
        # Parse different Git URL formats
        if 'github.com' in clean_url:
            parts = clean_url.split('/')
            if len(parts) >= 2:
                # Create full path for PURL: github.com/owner/repo
                full_path = f"github.com/{parts[-2]}/{repo_name}"
                return {
                    "name": repo_name,
                    "full_path": full_path
                }
        elif 'gitlab.com' in clean_url:
            parts = clean_url.split('/')
            if len(parts) >= 2:
                full_path = f"gitlab.com/{parts[-2]}/{repo_name}"
                return {
                    "name": repo_name,
                    "full_path": full_path
                }
        elif 'bitbucket.org' in clean_url:
            parts = clean_url.split('/')
            if len(parts) >= 2:
                full_path = f"bitbucket.org/{parts[-2]}/{repo_name}"
                return {
                    "name": repo_name,
                    "full_path": full_path
                }
        
        # Default fallback
        return {
            "name": repo_name,
            "full_path": repo_name
        }
    
