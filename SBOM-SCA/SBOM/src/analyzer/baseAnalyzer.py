#!/usr/bin/env python3
"""
Base Analyzer for SBOM Generator
Detects project type and provides common functionality
"""

import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from enum import Enum


class ProjectType(Enum):
    """Supported project types"""
    GOLANG = "golang"
    NPM = "npm"
    UNKNOWN = "unknown"


class BaseAnalyzer:
    """Base analyzer for detecting project types and common functionality"""
    
    def __init__(self, project_path: str):
        """
        Initialize base analyzer
        
        Args:
            project_path: Path to the project directory
        """
        self.project_path = Path(project_path)
        if not self.project_path.exists():
            raise FileNotFoundError(f"Project path does not exist: {project_path}")
        
        self.project_type = self._detect_project_type()
    
    def _detect_project_type(self) -> ProjectType:
        """
        Detect the project type based on project files
        
        Returns:
            ProjectType enum value
        """
        if self._is_golang_project():
            return ProjectType.GOLANG
        
        if self._is_npm_project():
            return ProjectType.NPM
        
        return ProjectType.UNKNOWN
    
    def _is_golang_project(self) -> bool:
        """Check if this is a Go project"""
        go_files = ["go.mod", "go.sum"]
        
        for file_name in go_files:
            if (self.project_path / file_name).exists():
                return True
        
        go_source_files = list(self.project_path.rglob("*.go"))
        if go_source_files:
            return True
        
        return False
    
    def _is_npm_project(self) -> bool:
        """Check if this is an NPM project (npm or pnpm)"""
        if (self.project_path / "package.json").exists():
            return True
        
        if (self.project_path / "package-lock.json").exists():
            return True
        
        if (self.project_path / "pnpm-lock.yaml").exists():
            return True
        
        package_json_files = []
        for pkg_json in self.project_path.rglob("package.json"):
            # Skip node_modules directories
            if "node_modules" not in str(pkg_json.relative_to(self.project_path)):
                package_json_files.append(pkg_json)
        
        if package_json_files:
            return True
        
        return False
    
    def get_project_type(self) -> ProjectType:
        """Get the detected project type"""
        return self.project_type
    
    def is_golang(self) -> bool:
        """Check if this is a Go project"""
        return self.project_type == ProjectType.GOLANG
    
    def is_npm(self) -> bool:
        """Check if this is an NPM project"""
        return self.project_type == ProjectType.NPM
    
    def get_project_info(self) -> Dict[str, Any]:
        """
        Get basic project information
        
        Returns:
            Dictionary with project information
        """
        return {
            "project_path": str(self.project_path),
            "project_type": self.project_type.value,
            "is_golang": self.is_golang(),
            "is_npm": self.is_npm()
        }
