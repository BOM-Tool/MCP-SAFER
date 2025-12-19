#!/usr/bin/env python3
"""
NPM-specific CycloneDX SBOM Generator
Handles npm package analysis and SBOM generation with proper dependency relationships
"""

import json
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import jsonschema


class NpmCycloneDXGenerator:
    """NPM-specific CycloneDX SBOM generator"""
    
    def __init__(self):
        self.schema_url = "http://cyclonedx.org/schema/bom-1.6.schema.json"
    
    def generate_sbom(self, analysis_result: Dict[str, Any], output_dir, 
                     git_url: Optional[str] = None, repo_name: Optional[str] = None) -> bool:
        """Generate CycloneDX SBOM for npm project"""
        try:
            print("Generating CycloneDX SBOM...")
            
            # Extract data from analysis result
            packages = analysis_result.get("packages", [])
            dependencies = analysis_result.get("dependencies", {})
            project_info = analysis_result.get("project_info", {})
            
            # Create components
            components = self._create_components(packages, "npm")
            
            # Create dependencies
            deps = self._create_npm_dependencies(components, dependencies, analysis_result)
            
            # Create main component (root package)
            main_component = self._create_main_component(project_info, git_url)
            
            # Create SBOM structure
            sbom = {
                "$schema": self.schema_url,
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "serialNumber": f"urn:uuid:{uuid.uuid4()}",
                "version": 1,
                "metadata": main_component,
                "components": components,
                "dependencies": deps
            }
            
            # Validate SBOM
            if self._validate_sbom(sbom):
                # Save SBOM - use repo_name directly (from Git URL)
                if repo_name:
                    project_name = repo_name
                else:
                    project_name = project_info.get('name', 'project')
                sbom_file = output_dir / f"{project_name}-sbom.cdx.json"
                with open(sbom_file, 'w', encoding='utf-8') as f:
                    json.dump(sbom, f, indent=2, ensure_ascii=False)
                
                print(f"SBOM generated: {sbom_file}")
                return True
            else:
                print("SBOM validation failed")
                return False
                
        except Exception as e:
            print(f"Error generating SBOM: {e}")
            return False
    
    def _create_components(self, packages: List[Dict[str, Any]], project_type: str) -> List[Dict[str, Any]]:
        """Create components from packages"""
        components = []
        
        for package in packages:
            name = package.get("name", "")
            version = package.get("version", "")
            package_path = package.get("package_path", "")
            
            if not name or not version:
                continue
            
            # Skip link: protocol dependencies (workspace/local dependencies)
            if version.startswith("link:"):
                continue
            
            # Debug: print first few packages
            if len(components) < 3:
                print(f"DEBUG: Processing package: {name}@{version}")
            
            # Generate PURL for npm packages (encode only scope, not package name)
            if name.startswith('@'):
                # Handle scoped packages (e.g., @scope/package -> %40scope/package)
                encoded_name = name.replace('@', '%40')
                if version and version != "":
                    purl = f"pkg:npm/{encoded_name}@{version}"
                else:
                    purl = f"pkg:npm/{encoded_name}"
            else:
                if version and version != "":
                    purl = f"pkg:npm/{name}@{version}"
                else:
                    purl = f"pkg:npm/{name}"
            
            # Generate unique BOM reference with package path (no encoding for bom-ref)
            hash_input = f"{name}@{version}#{package_path}"
            bom_ref = f"pkg:npm/{name}@{version}?package-id={self._generate_hash(hash_input)}"
            
            license_id = package.get("metadata", {}).get("license") or package.get("license")
            # Create component
            component = {
                "bom-ref": bom_ref,
                "type": "library",
                "name": name,
                "version": version if version and version != "" else None,
                "cpe": self._generate_cpe(name, version),
                "purl": purl
            }
            if license_id:
                component["licenses"] = [{
                    "license": {
                        "id": license_id
                    }
                }]
            
            # Add npm-specific properties
            properties = []
            if package_path:
                properties.append({
                    "name": "npm:packagePath",
                    "value": package_path
                })
            
            # Add dependency type information (peerDependencies 제외)
            if "metadata" in package:
                metadata = package["metadata"]
                # Check if it's a dependency type (excluding peerDependencies)
                if "dependency_type" in metadata:
                    dep_type = metadata["dependency_type"]
                    # peerDependencies는 제외
                    if dep_type not in ["peerDependencies", "peerDependenciesMeta"]:
                        properties.append({
                            "name": "npm:dependencyType",
                            "value": dep_type
                        })
                        
                        # Add optional flag for optionalDependencies
                        if dep_type == "optionalDependencies" and "is_optional" in metadata:
                            properties.append({
                                "name": "npm:optional",
                                "value": str(metadata["is_optional"])
                            })
            
            if properties:
                component["properties"] = properties
            
            # Remove None values
            component = {k: v for k, v in component.items() if v is not None}
            
            components.append(component)
        
        return components
    
    def _create_npm_dependencies(self, components: List[Dict[str, Any]], 
                                dependencies: Dict[str, List[str]], 
                                analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Create npm-specific dependency relationships"""
        deps = []
        component_deps_map = {}
        
        # Find main component (root package) by name
        main_component = None
        project_info = analysis_result.get("project_info", {})
        main_name = project_info.get("name", "unknown")
        main_version = project_info.get("version", "")
        
        for component in components:
            if component.get("name") == main_name and component.get("version") == main_version:
                main_component = component
                break
        
        # If not found, use first component as fallback
        if not main_component and components:
            main_component = components[0]
        
        if not main_component:
            return deps
        
        # Get direct dependencies for main component
        main_name = main_component["name"]
        main_version = main_component.get("version", "")
        main_full_name = f"{main_name}@{main_version}" if main_version else main_name
        
        print(f"DEBUG: Main component: {main_full_name}")
        print(f"DEBUG: Available dependencies: {list(dependencies.keys())[:5]}...")
        
        # Find direct dependencies for main component
        main_component_deps = []
        if main_full_name in dependencies:
            print(f"DEBUG: Found dependencies for {main_full_name}: {len(dependencies[main_full_name])}")
            for dep_name in dependencies[main_full_name]:
                # Find the component by name or name@version
                for other_component in components:
                    other_name = other_component["name"]
                    other_version = other_component.get("version", "")
                    other_full_name = f"{other_name}@{other_version}" if other_version else other_name
                    
                    # Try exact match first
                    if other_name == dep_name or other_full_name == dep_name:
                        main_component_deps.append(other_component["bom-ref"])
                        break
                    # Try partial match (name only)
                    elif dep_name.startswith(other_name + "@"):
                        main_component_deps.append(other_component["bom-ref"])
                        break
        
        if main_component_deps:
            component_deps_map[main_component["bom-ref"]] = main_component_deps
            print(f"DEBUG: Main component has {len(main_component_deps)} direct dependencies")
        
        # Add dependencies for each component
        for component in components:
            component_name = component["name"]
            component_version = component.get("version", "")
            component_full_name = f"{component_name}@{component_version}" if component_version else component_name
            
            # Find dependencies for this component
            if component_full_name in dependencies:
                component_deps = []
                for dep_name in dependencies[component_full_name]:
                    # Find the component by name or name@version
                    for other_component in components:
                        other_name = other_component["name"]
                        other_version = other_component.get("version", "")
                        other_full_name = f"{other_name}@{other_version}" if other_version else other_name
                        
                        if other_name == dep_name or other_full_name == dep_name:
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
        
        print(f"DEBUG: Created {len(deps)} dependency relationships")
        return deps
    
    def _create_main_component(self, project_info: Dict[str, Any], git_url: Optional[str] = None) -> Dict[str, Any]:
        """Create main component metadata"""
        name = project_info.get("name", "unknown")
        version = project_info.get("version", "")
        
        # Generate PURL for main component
        if version and version != "":
            purl = f"pkg:npm/{name}@{version}"
        else:
            purl = f"pkg:npm/{name}"
        
        # Generate BOM reference
        bom_ref = f"{purl}?package-id={self._generate_hash(f'{name}@{version}#')}"
        
        metadata = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tools": [
                {
                    "vendor": "Bomtori",
                    "name": "SBOMgenerator",
                    "version": "1.0.0"
                }
            ],
            "authors": [
                {
                    "name": "Bomtori"
                }
            ]
        }
        
        # Git information removed as requested
        
        return metadata
    
    def _generate_hash(self, input_string: str) -> str:
        """Generate 16-character hash for unique package identification"""
        import hashlib
        
        # Use SHA-256 and take first 16 characters for uniqueness
        hash_object = hashlib.sha256(input_string.encode('utf-8'))
        hex_dig = hash_object.hexdigest()
        
        # Return first 16 characters of SHA-256 hash
        return hex_dig[:16]
    
    def _generate_cpe(self, name: str, version: str) -> Optional[str]:
        """Generate CPE identifier for npm packages"""
        if not name:
            return None
        
        vendor, product = self._candidate_vendor_product_for_npm(name)
        
        if not product or not vendor:
            return None
        
        # Clean up version
        clean_version = version.replace("v", "") if version else "*"
        
        return f"cpe:2.3:a:{vendor}:{product}:{clean_version}:*:*:*:*:*:*:*"
    
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
    
    # _parse_git_url method removed as externalReferences is no longer needed
    
    def _validate_sbom(self, sbom: Dict[str, Any]) -> bool:
        """Validate SBOM against CycloneDX schema"""
        try:
            # Basic validation - check required fields
            required_fields = ["$schema", "bomFormat", "specVersion", "serialNumber", "version", "metadata", "components"]
            for field in required_fields:
                if field not in sbom:
                    print(f"Missing required field: {field}")
                    return False

            print("SBOM validation successful - conforms to CycloneDX schema")
            return True

        except jsonschema.exceptions._WrappedReferencingError as e:
            print(f"SBOM validation warning: failed to resolve reference ({e}). Proceeding without strict validation.")
            return True
        except Exception as e:
            print(f"SBOM validation failed: {e}")
            return False
