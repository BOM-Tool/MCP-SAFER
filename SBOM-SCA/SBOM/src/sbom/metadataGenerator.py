#!/usr/bin/env python3
"""
Metadata Generator for Go Module Analysis
Generates separate JSON file with MVS and dependency metadata
"""

import json
from datetime import datetime, timezone
from typing import Dict, List, Any


class MetadataGenerator:
    """Generator for Go module metadata JSON file"""
    
    def __init__(self):
        """Initialize the metadata generator"""
        pass
    
    def generate_metadata(self, analysis_result: Dict, project_path: str) -> Dict:
        """
        Generate metadata JSON with MVS and dependency information
        
        Args:
            analysis_result: Analysis result from Go analyzer
            project_path: Path to the Go project
            
        Returns:
            Dictionary containing metadata information
        """
        # Extract packages and their metadata
        packages = analysis_result.get("packages", [])
        
        # Create component metadata
        components_metadata = []
        for package in packages:
            name = package.get("name", "")
            version = package.get("version", "")
            metadata = package.get("metadata", {})
            
            component_metadata = {
                "name": name,
                "version": version,
                "mvs_selected": metadata.get("is_mvs_selected", False),
                "is_direct_dependency": metadata.get("is_direct", False)
            }
            components_metadata.append(component_metadata)
        
        # Create summary statistics
        mvs_selected_count = sum(1 for comp in components_metadata if comp["mvs_selected"])
        direct_dependencies_count = sum(1 for comp in components_metadata if comp["is_direct_dependency"])
        total_components = len(components_metadata)
        
        # Identify root package (if exists in analysis_result)
        # Root package is not a dependency, so we exclude it from indirect dependencies count
        root_package = analysis_result.get("root_package", {})
        root_package_name = root_package.get("name", "")
        root_package_version = root_package.get("version", "")
        
        # Count root package if it exists in components
        root_package_count = 0
        if root_package_name and root_package_version:
            for comp in components_metadata:
                if (comp["name"] == root_package_name and 
                    comp["version"] == root_package_version and 
                    not comp["is_direct_dependency"]):
                    root_package_count = 1
                    break
        
        # Calculate indirect dependencies: total - direct - root
        indirect_dependencies_count = total_components - direct_dependencies_count - root_package_count
        
        # Create metadata structure
        metadata = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "project_path": project_path,
            "root_module": analysis_result.get("root_module", ""),
            "summary": {
                "total_components": total_components,
                "mvs_selected_count": mvs_selected_count,
                "non_mvs_count": total_components - mvs_selected_count,
                "direct_dependencies_count": direct_dependencies_count,
                "indirect_dependencies_count": indirect_dependencies_count
            },
            "components": components_metadata
        }
        
        return metadata
    
    def save_metadata(self, metadata: Dict, output_path: str) -> None:
        """
        Save metadata to JSON file
        
        Args:
            metadata: Metadata dictionary
            output_path: Path to save the metadata file
        """
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
