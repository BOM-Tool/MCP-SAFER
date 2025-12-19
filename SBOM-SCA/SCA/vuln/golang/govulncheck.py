#!/usr/bin/env python3
"""
govulncheck auto-execution module
"""

import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Tuple


class GovulnCheckRunner:
    """govulncheck runner"""
    
    def __init__(self, project_path: Optional[str] = None):
        if project_path:
            project = Path(project_path).expanduser().resolve()
            if (project / 'go.mod').exists():
                self.project_path = project
            else:
                go_mod = self._find_go_mod(project)
                self.project_path = go_mod.parent if go_mod else project
        else:
            current = Path.cwd()
            go_mod = self._find_go_mod(current)
            self.project_path = go_mod.parent if go_mod else current
        
        self.govulncheck_path = None
        self._find_govulncheck()
    
    def _find_go_mod(self, start_path: Path) -> Optional[Path]:
        """Find go.mod by traversing up directories (max 5 levels)"""
        current = start_path.resolve()
        max_levels = 5
        level = 0
        
        while current != current.parent and level < max_levels:
            go_mod = current / 'go.mod'
            if go_mod.exists():
                return go_mod
            current = current.parent
            level += 1
        
        return None
    
    def _find_govulncheck(self) -> bool:
        """Find govulncheck executable"""
        try:
            result = subprocess.run(
                ['go', 'env', 'GOPATH'],
                capture_output=True,
                text=True,
                check=True
            )
            gopath = result.stdout.strip()
            if gopath:
                self.govulncheck_path = Path(gopath) / 'bin' / 'govulncheck'
                if self.govulncheck_path.exists():
                    return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        try:
            result = subprocess.run(
                ['which', 'govulncheck'],
                capture_output=True,
                text=True,
                check=True
            )
            self.govulncheck_path = Path(result.stdout.strip())
            if self.govulncheck_path.exists():
                return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        return False
    
    def run(self, output_file: Optional[str] = None, verbose: bool = True) -> Tuple[bool, Optional[str]]:
        """
        Run govulncheck
        
        Args:
            output_file: Output file path (use temp file if None)
            verbose: Use verbose output
        
        Returns:
            (success, output_file_path or None)
        """
        if not self.govulncheck_path or not self.govulncheck_path.exists():
            return False, None
        
        if output_file:
            output_path = Path(output_file)
        else:
            output_dir = self.project_path / 'output'
            if not output_dir.exists():
                output_dir = self.project_path
                output_dir.mkdir(parents=True, exist_ok=True)
            
            temp_file = tempfile.NamedTemporaryFile(
                mode='w',
                suffix='-vuln-detailed.txt',
                delete=False,
                dir=str(output_dir)
            )
            output_path = Path(temp_file.name)
            temp_file.close()
        
        cmd = [str(self.govulncheck_path)]
        if verbose:
            cmd.append('-show')
            cmd.append('verbose')
        cmd.append('./...')
        
        try:
            print(f"   Running govulncheck: {' '.join(cmd)}")
            print(f"   Working directory: {self.project_path}")
            
            go_mod = self.project_path / 'go.mod'
            if not go_mod.exists():
                go_mod = self._find_go_mod(self.project_path)
                if go_mod:
                    self.project_path = go_mod.parent
                    print(f"   Found go.mod: {self.project_path}")
                else:
                    print(f"   Error: go.mod not found")
                    print(f"   Current path: {self.project_path}")
                    print(f"   Searched parent directories but go.mod not found")
                    print(f"   Tips:")
                    print(f"      - Use --project-path to specify Go module directory")
                    print(f"      - Run from Go project directory")
                    print(f"      - Use --vuln-file to use existing result file (recommended)")
                    return False, None
            
            with open(output_path, 'w', encoding='utf-8') as f:
                result = subprocess.run(
                    cmd,
                    cwd=self.project_path,
                    stdout=f,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False
                )
            
            # govulncheck exit codes: 0=success, 1=error, 2=no vuln, 3=vuln found
            if result.returncode in [0, 2, 3]:
                if output_path.exists() and output_path.stat().st_size > 0:
                    print(f"   Saved results: {output_path}")
                    return True, str(output_path)
                else:
                    if not output_path.exists() or output_path.stat().st_size == 0:
                        with open(output_path, 'w', encoding='utf-8') as f:
                            f.write("# No vulnerabilities found or govulncheck completed successfully\n")
                    print(f"   Saved results: {output_path}")
                    return True, str(output_path)
            else:
                print(f"   Error: govulncheck execution failed")
                print(f"   Exit code: {result.returncode}")
                if result.stderr:
                    print(f"   Error message: {result.stderr[:500]}")
                return False, None
                
        except Exception as e:
            print(f"   Error: Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            return False, None
    
    def is_available(self) -> bool:
        """Check if govulncheck is available"""
        return self.govulncheck_path is not None and self.govulncheck_path.exists()
