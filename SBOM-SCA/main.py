#!/usr/bin/env python3
"""
Bomtori - SBOM and SCA Analysis Tool
Performs both SBOM and SCA analysis with a GitHub URL input.
"""

import argparse
import sys
import subprocess
import shutil
import json
import os
import urllib.request
import urllib.error
import ssl
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple

# Add SBOM and SCA directories to path
sys.path.insert(0, str(Path(__file__).parent / "SBOM" / "src"))
sys.path.insert(0, str(Path(__file__).parent / "SBOM"))

from analyzer.baseAnalyzer import BaseAnalyzer, ProjectType
from analyzer.golangAnalyzer import GolangAnalyzer
from analyzer.npmAnalyzer import NpmAnalyzer
from sbom.golangCyclonedxGenerator import CycloneDXGenerator
from sbom.npmCycloneDXGenerator import NpmCycloneDXGenerator
from sbom.metadataGenerator import MetadataGenerator


def print_banner():
    """Print Bomtori banner"""
    COLOR1 = '\033[38;2;108;93;83m'
    COLOR2 = '\033[38;2;159;132;115m'
    COLOR3 = '\033[38;2;199;177;153m'
    COLOR4 = '\033[38;2;223;211;195m'
    RESET = '\033[0m'
    
    banner = f"""
{COLOR4}██████╗  ██████╗ ███╗   ███╗████████╗ ██████╗ ██████╗ ██╗{RESET}
{COLOR3}██╔══██╗██╔═══██╗████╗ ████║╚══██╔══╝██╔═══██╗██╔══██╗██║{RESET}
{COLOR2}██████╔╝██║   ██║██╔████╔██║   ██║   ██║   ██║██████╔╝██║{RESET}
{COLOR2}██╔══██╗██║   ██║██║╚██╔╝██║   ██║   ██║   ██║██╔══██╗██║{RESET}
{COLOR1}██████╔╝╚██████╔╝██║ ╚═╝ ██║   ██║   ╚██████╔╝██║  ██║██║{RESET}
{COLOR1}╚═════╝  ╚═════╝ ╚═╝     ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝{RESET}
    """
    print(banner)
    print(f"{COLOR2}SBOM & SCA Analysis Tool{RESET}")
    print()


def clone_repository(git_url, target_dir):
    """Clone Git repository to target directory"""
    try:
        print(f"Cloning repository: {git_url}")
        
        # Remove target directory if it exists
        if Path(target_dir).exists():
            shutil.rmtree(target_dir)
        
        subprocess.run(
            ["git", "clone", git_url, str(target_dir)],
            check=True,
            capture_output=True
        )
        # Extract repository name from URL
        repo_name = git_url.split('/')[-1].replace('.git', '')
        print(f"Repository cloned successfully: {repo_name}")
        return repo_name
    except subprocess.CalledProcessError as e:
        print(f"Failed to clone repository: {e}")
        return None


def run_sbom_analysis(source_dir, output_dir, project_type, git_url=None, repo_name=None):
    """Run SBOM analysis based on project type"""
    print("\n" + "=" * 60)
    print("Starting SBOM Analysis")
    print("=" * 60)
    
    if project_type == ProjectType.GOLANG:
        return analyze_go_sbom(source_dir, output_dir, git_url)
    elif project_type == ProjectType.NPM:
        return analyze_npm_sbom(source_dir, output_dir, git_url, repo_name)
    else:
        print(f"Unsupported project type: {project_type.value}")
        return None


def analyze_go_sbom(source_dir, output_dir, git_url=None):
    """Analyze Go project and generate SBOM"""
    print(f"Analyzing Go project SBOM: {source_dir}")
    
    try:
        # Initialize Go analyzer
        analyzer = GolangAnalyzer()
        
        # Analyze the project
        analysis_result = analyzer.analyze(str(source_dir), git_url)
        print(f"Analysis completed: {len(analysis_result['packages'])} packages found")
        
        # Generate CycloneDX SBOM
        print("Generating CycloneDX SBOM...")
        sbom_generator = CycloneDXGenerator()
        
        author_info = {"name": "Bomtori"}
        sbom = sbom_generator.generate_sbom(
            analysis_result, str(source_dir), author_info, git_url, "golang"
        )
        
        # Generate metadata JSON
        print("Generating metadata...")
        metadata_generator = MetadataGenerator()
        metadata = metadata_generator.generate_metadata(analysis_result, str(source_dir))
        
        # Save files
        repo_name = Path(source_dir).name
        safe_repo_name = repo_name.replace('@', '_').replace('/', '_')
        sbom_file = output_dir / f"{safe_repo_name}-sbom.cdx.json"
        metadata_file = output_dir / f"{safe_repo_name}-metadata.json"
        
        # Save SBOM
        with open(sbom_file, 'w', encoding='utf-8') as f:
            json.dump(sbom, f, indent=2, ensure_ascii=False)
        
        # Save metadata
        metadata_generator.save_metadata(metadata, str(metadata_file))
        
        print(f"SBOM generated: {sbom_file.name}")
        print(f"Metadata generated: {metadata_file.name}")
        print(f"  - Total components: {metadata['summary']['total_components']}")
        print(f"  - Direct dependencies: {metadata['summary']['direct_dependencies_count']}")
        print(f"  - Indirect dependencies: {metadata['summary']['indirect_dependencies_count']}")
        
        return {
            'sbom_file': sbom_file,
            'metadata_file': metadata_file,
            'analysis_result': analysis_result
        }
        
    except Exception as e:
        print(f"SBOM analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def analyze_npm_sbom(source_dir, output_dir, git_url=None, repo_name=None):
    """Analyze NPM project and generate SBOM"""
    print(f"Analyzing NPM project SBOM: {source_dir}")
    
    try:
        # Initialize NPM analyzer
        analyzer = NpmAnalyzer(str(source_dir))
        
        # Analyze the project
        analysis_result = analyzer.analyze()
        print(f"Analysis completed: {len(analysis_result['packages'])} packages found")
        
        # Generate CycloneDX SBOM
        print("Generating CycloneDX SBOM...")
        sbom_generator = NpmCycloneDXGenerator()
        
        # Use provided repo_name if available, otherwise extract from source_dir
        if not repo_name:
            repo_name = Path(source_dir).name
        
        success = sbom_generator.generate_sbom(
            analysis_result=analysis_result,
            output_dir=output_dir,
            git_url=git_url,
            repo_name=repo_name
        )
        
        if not success:
            print("Failed to generate SBOM")
            return None
        
        # Generate metadata JSON
        print("Generating metadata...")
        metadata_generator = MetadataGenerator()
        metadata = metadata_generator.generate_metadata(analysis_result, str(source_dir))
        
        # Save metadata - use repo_name directly
        metadata_file = output_dir / f"{repo_name}-metadata.json"
        metadata_generator.save_metadata(metadata, str(metadata_file))
        
        print(f"Metadata generated: {metadata_file.name}")
        print(f"  - Total components: {metadata['summary']['total_components']}")
        print(f"  - Direct dependencies: {metadata['summary']['direct_dependencies_count']}")
        print(f"  - Indirect dependencies: {metadata['summary']['indirect_dependencies_count']}")
        
        return {
            'metadata_file': metadata_file,
            'analysis_result': analysis_result
        }
        
    except Exception as e:
        print(f"SBOM analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def run_sca_analysis(source_dir, output_dir, project_type, repo_name=None):
    """Run SCA analysis based on project type"""
    print("\n" + "=" * 60)
    print("Starting SCA Analysis")
    print("=" * 60)
    print("SCA includes: Call Graph Analysis")
    
    if project_type == ProjectType.GOLANG:
        print("\n[1/2] Call Graph Analysis")
        callgraph_result = analyze_go_callgraph(source_dir, output_dir, repo_name)
        return callgraph_result
    elif project_type == ProjectType.NPM:
        print("\n[1/2] Call Graph Analysis")
        callgraph_result = analyze_npm_callgraph(source_dir, output_dir, repo_name)
        return callgraph_result
    else:
        print(f"Unsupported project type: {project_type.value}")
        return None


def analyze_go_callgraph(source_dir, output_dir, repo_name=None):
    """Analyze Go call graph"""
    print(f"Analyzing Go Call Graph: {source_dir}")
    
    try:
        # Go call graph analysis script path
        callgraph_script = Path(__file__).parent / "SCA" / "callGraph" / "golang" / "goCallGraph.go"
        
        if not callgraph_script.exists():
            print(f"Call Graph script not found: {callgraph_script}")
            return None
        
        # Execute Go call graph
        print("Running Go SSA Call Graph analysis...")
        
        # Use repo_name if provided, otherwise use directory name
        if not repo_name:
            repo_name = Path(source_dir).name
        safe_name = repo_name.replace('@', '_').replace('/', '_').replace(' ', '_')
        
        # Pass OUTPUT_DIR and REPO_NAME as environment variables
        env = os.environ.copy()
        env['OUTPUT_DIR'] = str(output_dir.resolve())  # Use absolute path
        if repo_name:
            env['REPO_NAME'] = repo_name
        
        result = subprocess.run(
            ["go", "run", str(callgraph_script), str(source_dir)],
            cwd=callgraph_script.parent,
            capture_output=True,
            text=True,
            env=env
        )
        
        # Always print output to see what's happening
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print("Errors:", result.stderr)
        
        if result.returncode != 0:
            print(f"Warning: Call Graph analysis encountered issues (continuing)")
        
        # Output file is now directly in output_dir
        output_file = output_dir / f"{safe_name}-callGraph.json"
        
        if output_file.exists():
            print(f"Call Graph generated: {output_file.name}")
            
            # Print statistics
            with open(output_file, 'r', encoding='utf-8') as f:
                callgraph_data = json.load(f)
            
            print(f"  - Packages: {callgraph_data.get('packages', 0)}")
            print(f"  - Functions: {callgraph_data.get('functions', 0)}")
            print(f"  - Edges: {callgraph_data.get('edges', 0)}")
            
            return {'callgraph_file': output_file, 'data': callgraph_data}
        else:
            print("Warning: Call Graph output file not found")
            return None
            
    except FileNotFoundError:
        print("Go command not found. Please ensure Go is installed.")
        return None
    except Exception as e:
        print(f"Call Graph analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def analyze_npm_callgraph(source_dir, output_dir, repo_name=None):
    """Analyze NPM call graph"""
    print(f"Analyzing TypeScript/JavaScript Call Graph: {source_dir}")
    
    try:
        # Detect package manager (pnpm or npm)
        source_dir_path = Path(source_dir)
        node_modules_path = source_dir_path / "node_modules"
        package_json_path = source_dir_path / "package.json"
        pnpm_lock_path = source_dir_path / "pnpm-lock.yaml"
        
        is_pnpm = pnpm_lock_path.exists()
        
        if package_json_path.exists() and not node_modules_path.exists():
            if is_pnpm:
                print("Detected pnpm project (pnpm-lock.yaml found)")
                print("node_modules not found, running pnpm install...")
                try:
                    install_result = subprocess.run(
                        ["pnpm", "install", "--ignore-scripts", "--no-frozen-lockfile"],
                        cwd=str(source_dir_path),
                        capture_output=True,
                        text=True,
                        timeout=300
                    )
                    if install_result.returncode == 0:
                        print("pnpm install completed successfully")
                    else:
                        print(f"Warning: pnpm install had issues (continuing anyway)")
                        if install_result.stderr:
                            print(f"  stderr: {install_result.stderr[:200]}")
                except subprocess.TimeoutExpired:
                    print("Warning: pnpm install timed out (continuing anyway)")
                except FileNotFoundError:
                    print("Warning: pnpm not found. Please run 'pnpm install' manually")
                except Exception as e:
                    print(f"Warning: Failed to run pnpm install: {e}")
            else:
                print("node_modules not found, running npm install...")
                try:
                    install_result = subprocess.run(
                        ["npm", "install"],
                        cwd=str(source_dir_path),
                        capture_output=True,
                        text=True,
                        timeout=300
                    )
                    if install_result.returncode == 0:
                        print("npm install completed successfully")
                    else:
                        print(f"Warning: npm install had issues (continuing anyway)")
                        if install_result.stderr:
                            print(f"  stderr: {install_result.stderr[:200]}")
                except subprocess.TimeoutExpired:
                    print("Warning: npm install timed out (continuing anyway)")
                except FileNotFoundError:
                    print("Warning: npm not found. Please run 'npm install' manually")
                except Exception as e:
                    print(f"Warning: Failed to run npm install: {e}")
        
        # TypeScript call graph script path
        callgraph_script = Path(__file__).parent / "SCA" / "callGraph" / "npm" / "tsCallGraph.ts"
        
        if not callgraph_script.exists():
            print(f"Call Graph script not found: {callgraph_script}")
            return None
        
        # Check package.json
        package_json_path = callgraph_script.parent / "package.json"
        if not package_json_path.exists():
            print(f"package.json not found: {package_json_path}")
            return None
        
        # Execute TypeScript call graph
        print("Running TypeScript Call Graph analysis...")
        # Use repo_name if provided, otherwise use package.json name
        if repo_name:
            safe_name = repo_name
        else:
            with open(Path(source_dir) / "package.json", 'r', encoding='utf-8') as f:
                pkg_data = json.load(f)
            project_name = pkg_data.get('name', Path(source_dir).name)
            # Extract last segment from @org/package-name
            safe_name = project_name.replace('@', '').replace('/', '-')
            if '/' in project_name:
                safe_name = project_name.split('/')[-1]
        
        # Run tsx with cwd set to Bomtori root
        # Pass repo_name and output_dir as environment variables
        env = os.environ.copy()
        if repo_name:
            env['REPO_NAME'] = repo_name
        env['OUTPUT_DIR'] = str(output_dir.resolve())  # Use absolute path
        result = subprocess.run(
            ["npx", "tsx", str(callgraph_script), str(source_dir), "--analyze-node-modules"],
            cwd=str(Path(__file__).parent),  # Use Bomtori root as cwd
            capture_output=True,
            text=True,
            env=env
        )
        
        if result.returncode != 0:
            print(f"Warning: Call Graph analysis encountered issues (continuing)")
            print(f"   stderr: {result.stderr[:500]}")
        
        # Output file is now in output_dir (passed via OUTPUT_DIR env var)
        output_file = output_dir / f"{safe_name}-callGraph.json"
        
        if output_file.exists():
            print(f"Call Graph generated: {output_file.name}")
            
            # Print statistics
            with open(output_file, 'r', encoding='utf-8') as f:
                callgraph_data = json.load(f)
            
            print(f"  - Files: {callgraph_data.get('files', 0)}")
            print(f"  - Functions: {callgraph_data.get('functions', 0)}")
            print(f"  - Edges: {callgraph_data.get('edges', 0)}")
            
            return {'callgraph_file': output_file, 'data': callgraph_data}
        else:
            print("Warning: Call Graph output file not found")
            return None
            
    except FileNotFoundError:
        print("npx or tsx not found. Please ensure Node.js is installed.")
        return None
    except Exception as e:
        print(f"Call Graph analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def run_vulnerability_analysis(source_dir, output_dir, repo_name, project_type):
    """Run vulnerability reachability analysis"""
    print("\n[2/2] Vulnerability Reachability Analysis")
    
    try:
        # Import vulnerability analysis module based on project type
        sys.path.insert(0, str(Path(__file__).parent / "SCA" / "vuln"))
        
        # Convert to Path objects
        output_dir = Path(output_dir)
        source_dir = Path(source_dir)
        
        # Find call graph file
        safe_name = repo_name.replace('@', '_').replace('/', '_').replace(' ', '_')
        callgraph_file = output_dir / f"{safe_name}-callGraph.json"
        
        if not callgraph_file.exists():
            print(f"Warning: Call Graph file not found: {callgraph_file}")
            print("Skipping vulnerability analysis")
            return None
        
        # Import and run appropriate analyzer based on project type
        if project_type == ProjectType.GOLANG:
            from golang.analyzer import run_vulnerability_analysis as run_go_vuln_analysis
            result = run_go_vuln_analysis(
                callgraph_file=str(callgraph_file),
                project_path=str(source_dir),
                output_file=str(output_dir / f"{safe_name}-reachability.json")
            )
        elif project_type == ProjectType.NPM:
            from npm.analyzer import run_vulnerability_analysis as run_npm_vuln_analysis
            # For npm/pnpm, we also need audit.json
            # Check in source_dir first, then try to generate it
            audit_file = Path(source_dir) / "audit.json"
            
            # Detect package manager (pnpm or npm)
            pnpm_lock_path = Path(source_dir) / "pnpm-lock.yaml"
            is_pnpm = pnpm_lock_path.exists()
            
            if not audit_file.exists():
                # Try to generate audit.json
                print(f"audit.json not found, attempting to generate it...")
                import subprocess
                try:
                    # Use pnpm audit for pnpm projects, npm audit for npm projects
                    if is_pnpm:
                        print("Detected pnpm project, running pnpm audit...")
                        audit_command = ['pnpm', 'audit', '--json']
                        package_manager = 'pnpm'
                    else:
                        print("Running npm audit...")
                        audit_command = ['npm', 'audit', '--json']
                        package_manager = 'npm'
                    
                    # Change to source directory and run audit
                    print(f"   Executing: {' '.join(audit_command)} in {source_dir}")
                    result = subprocess.run(
                        audit_command,
                        cwd=str(source_dir),
                        capture_output=True,
                        text=True,
                        timeout=120  # Increase timeout for large projects
                    )
                    
                    # Log stdout and stderr for debugging
                    if result.stdout:
                        print(f"   Audit stdout length: {len(result.stdout)} bytes")
                    if result.stderr:
                        print(f"   Audit stderr: {result.stderr[:200]}")
                    print(f"   Audit exit code: {result.returncode}")
                    
                    if result.returncode == 0 or (result.returncode != 0 and result.stdout):
                        # audit can return non-zero exit code even with valid JSON output
                        # Check if output is valid JSON
                        try:
                            import json
                            audit_data = json.loads(result.stdout)
                            
                            # Check if audit_data is a dict or list
                            if isinstance(audit_data, list):
                                # pnpm audit sometimes returns a list directly
                                print(f"   Warning: pnpm audit returned a list, not a dict. This format is not fully supported.")
                                vuln_count = len(audit_data) if audit_data else 0
                                print(f"   Found {vuln_count} items in pnpm audit list format")
                            elif isinstance(audit_data, dict):
                                # Check if audit has vulnerabilities
                                if 'vulnerabilities' in audit_data:
                                    vuln_count = len(audit_data['vulnerabilities'])
                                    print(f"   Found {vuln_count} vulnerable packages in audit.json")
                                elif 'actions' in audit_data:
                                    # pnpm format
                                    # pnpm audit 구조: {"actions": [{"action": "update", "module": "package", "resolves": [{"id": 123, ...}]}]}
                                    actions = audit_data.get('actions', [])
                                    vuln_count = 0
                                    for action in actions:
                                        if isinstance(action, dict):
                                            # resolves는 리스트 (딕셔너리가 아님!)
                                            resolves = action.get('resolves', [])
                                            if isinstance(resolves, list):
                                                # resolves 리스트의 각 항목이 하나의 취약점
                                                vuln_count += len(resolves)
                                    print(f"   Found {vuln_count} vulnerabilities in pnpm audit format")
                                else:
                                    print(f"   Warning: No vulnerabilities field found in audit output")
                            else:
                                print(f"   Warning: Unexpected audit data type: {type(audit_data)}")
                            
                            # Valid JSON, save it to both source_dir and output_dir
                            audit_file.write_text(result.stdout, encoding='utf-8')
                            print(f"   Generated audit.json: {audit_file}")
                            
                            # Also save to output_dir for inspection
                            output_audit_file = output_dir / f"{safe_name}-audit.json"
                            output_audit_file.write_text(result.stdout, encoding='utf-8')
                            print(f"   Saved audit.json to output directory: {output_audit_file}")
                            
                        except json.JSONDecodeError as e:
                            print(f"   Warning: {package_manager} audit output is not valid JSON: {e}")
                            print(f"   Output preview: {result.stdout[:200]}")
                            print("Skipping vulnerability analysis")
                            return None
                    else:
                        print(f"   Warning: Failed to run {package_manager} audit (exit code: {result.returncode})")
                        if result.stderr:
                            print(f"   Error: {result.stderr[:500]}")
                        print(f"   Run '{package_manager} audit --json > audit.json' in the project directory")
                        print("Skipping vulnerability analysis")
                        return None
                except FileNotFoundError:
                    print(f"Warning: {package_manager} not found. Please install Node.js and {package_manager}")
                    print(f"Or run '{package_manager} audit --json > audit.json' in the project directory")
                    print("Skipping vulnerability analysis")
                    return None
                except Exception as e:
                    print(f"Warning: Failed to generate audit.json: {e}")
                    print(f"Run '{package_manager} audit --json > audit.json' in the project directory")
                    print("Skipping vulnerability analysis")
                    return None
            
            result = run_npm_vuln_analysis(
                callgraph_file=str(callgraph_file),
                audit_file=str(audit_file),
                project_path=str(source_dir),
                output_file=str(output_dir / f"{safe_name}-reachability.json")
            )
        else:
            print(f"Warning: Vulnerability analysis not supported for project type: {project_type.value}")
            return None
        
        return result
        
    except ImportError as e:
        print(f"Warning: Could not import vulnerability analysis module: {e}")
        print("Skipping vulnerability analysis")
        return None
    except Exception as e:
        print(f"Warning: Vulnerability analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def generate_summary_report(output_dir, repo_name, sbom_result, sca_result, vuln_result=None):
    """Generate summary report"""
    print("\n" + "=" * 60)
    print("Analysis Summary Report")
    print("=" * 60)
    
    summary = {
        "repository": repo_name,
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        "sbom": {},
        "sca": {},
        "vulnerability": {}
    }
    
    # Add SBOM information
    if sbom_result and 'analysis_result' in sbom_result:
        analysis = sbom_result['analysis_result']
        summary['sbom'] = {
            "packages_found": len(analysis.get('packages', [])),
            "status": "Success"
        }
    else:
        summary['sbom']['status'] = "Failed"
    
    # Add SCA information
    if sca_result and 'data' in sca_result:
        sca_data = sca_result['data']
        summary['sca'] = {
            "functions": sca_data.get('functions', 0),
            "edges": sca_data.get('edges', 0),
            "status": "Success"
        }
    else:
        summary['sca']['status'] = "Failed"
    
    # Add Vulnerability information
    if vuln_result:
        vuln_summary = vuln_result.get('summary', {})
        vulnerabilities = vuln_result.get('vulnerabilities', [])
        
        # Calculate statistics from vulnerabilities array
        # Check both 'reachable' field and 'reaching_entry_points' existence
        total_reachable_funcs = 0
        total_unreachable_funcs = 0
        reachable_vulns = 0
        unreachable_vulns = 0
        total_funcs = 0
        
        for vuln in vulnerabilities:
            has_reachable = False
            for func_result in vuln.get('vulnerable_functions', []):
                total_funcs += 1
                
                # Check if function is reachable
                # Either 'reachable' is True OR 'reaching_entry_points' exists
                is_reachable = func_result.get('reachable', False)
                reaching_entries = func_result.get('reaching_entry_points', [])
                
                if is_reachable or reaching_entries:
                    total_reachable_funcs += 1
                    has_reachable = True
                else:
                    total_unreachable_funcs += 1
            
            if has_reachable:
                reachable_vulns += 1
            else:
                unreachable_vulns += 1
        
        # If total_funcs is 0, try to get from summary (fallback for golang analyzer format)
        if total_funcs == 0:
            total_funcs = vuln_summary.get('total_vulnerable_functions', 0)
            total_reachable_funcs = vuln_summary.get('reachable_functions', 0)
            total_unreachable_funcs = vuln_summary.get('unreachable_functions', 0)
        
        # Calculate rates
        total_vulns = vuln_summary.get('total_vulnerabilities', len(vulnerabilities))
        if total_vulns > 0:
            vuln_rate = f"{(reachable_vulns / total_vulns * 100):.1f}%"
        else:
            vuln_rate = "0%"
        
        if total_funcs > 0:
            func_rate = f"{(total_reachable_funcs / total_funcs * 100):.1f}%"
        else:
            func_rate = "0%"
        
        summary['vulnerability'] = {
            # Overall vulnerability statistics
            "total_vulnerabilities": total_vulns,
            "reachable_vulnerabilities": reachable_vulns,
            "unreachable_vulnerabilities": unreachable_vulns,
            "vulnerability_reachability_rate": vuln_rate,
            # Vulnerable function statistics
            "total_vulnerable_functions": total_funcs,
            "reachable_functions": total_reachable_funcs,
            "unreachable_functions": total_unreachable_funcs,
            "function_reachability_rate": func_rate,
            "status": "Success"
        }
    else:
        summary['vulnerability']['status'] = "Skipped or Failed"
    
    # Save summary report
    summary_file = output_dir / f"{repo_name}-summary.json"
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    
    print(f"Summary report generated: {summary_file.name}")
    print(f"\n" + "=" * 60)
    print("Analysis Results")
    print("=" * 60)
    
    # SBOM
    print(f"\nSBOM:")
    print(f"  Status: {summary['sbom'].get('status', 'Unknown')}")
    if summary['sbom'].get('status') == 'Success':
        print(f"  Packages: {summary['sbom']['packages_found']}")
    
    # SCA (includes Call Graph and Vulnerability)
    print(f"\nSCA:")
    print(f"  Status: {summary['sca'].get('status', 'Unknown')}")
    
    # Call Graph (within SCA)
    if summary['sca'].get('status') == 'Success':
        print(f"  Call Graph:")
        print(f"    - Functions: {summary['sca']['functions']}")
        print(f"    - Edges: {summary['sca']['edges']}")
    
    # Vulnerability Analysis (within SCA)
    if summary.get('vulnerability') and summary['vulnerability'].get('status') != 'N/A':
        print(f"  Vulnerability Analysis:")
        print(f"    Status: {summary['vulnerability'].get('status', 'Unknown')}")
        if summary['vulnerability'].get('status') == 'Success':
            vuln = summary['vulnerability']
            print(f"    Vulnerabilities:")
            print(f"      - Total: {vuln.get('total_vulnerabilities', 0)}")
            print(f"      - Reachable: {vuln.get('reachable_vulnerabilities', 0)}")
            print(f"      - Unreachable: {vuln.get('unreachable_vulnerabilities', 0)}")
            print(f"      - Reachability rate: {vuln.get('vulnerability_reachability_rate', '0%')}")
            print(f"    Vulnerable Functions:")
            print(f"      - Total: {vuln.get('total_vulnerable_functions', 0)}")
            print(f"      - Reachable: {vuln.get('reachable_functions', 0)}")
            print(f"      - Unreachable: {vuln.get('unreachable_functions', 0)}")
            print(f"      - Reachability rate: {vuln.get('function_reachability_rate', '0%')}")
    else:
        print(f"  Vulnerability Analysis: N/A (not supported for this project type)")


def _fetch_nvd_details(cve_id: str) -> Dict[str, Any]:
    """Fetch CVSS/Severity information from NVD as a fallback."""
    details = {'cvss': None, 'severity': None}
    
    if not cve_id:
        return details
    
    try:
        nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        req = urllib.request.Request(nvd_url)
        req.add_header('User-Agent', 'Bomtori-dashboard')
        
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        with urllib.request.urlopen(req, context=ssl_context, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
        
        vulnerabilities = data.get('vulnerabilities', [])
        if not vulnerabilities:
            return details
        
        cve_info = vulnerabilities[0].get('cve', {})
        metrics = cve_info.get('metrics', {})
        
        for metric_key in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
            metric_list = metrics.get(metric_key)
            if not metric_list:
                continue
            
            metric = metric_list[0]
            cvss_data = metric.get('cvssData', {})
            
            score = cvss_data.get('baseScore')
            severity = cvss_data.get('baseSeverity')

            if score is not None:
                try:
                    details['cvss'] = round(float(score), 1)
                except (TypeError, ValueError):
                    pass
            
            if severity:
                details['severity'] = str(severity).upper()
            
            # Use first available metric
            break
    except Exception:
        pass
    
    return details


def _fetch_advisory_details(advisory_id: str) -> Dict[str, Any]:
    """
    Fetch CVE, CVSS, and detailed description from OSV.dev API
    
    Args:
        advisory_id: GHSA ID or CVE ID
        
    Returns:
        Dictionary with CVE, CVSS, description, and fixed versions
    """
    details = {
        'cve': None,
        'cvss': None,
        'severity': None,
        'description': None,
        'fixed_version': None,
        'all_fixed_versions': []
    }
    
    try:
        osv_url = f"https://api.osv.dev/v1/vulns/{advisory_id}"
        req = urllib.request.Request(osv_url)
        req.add_header('Content-Type', 'application/json')
        req.add_header('User-Agent', 'Bomtori-dashboard')
        
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        with urllib.request.urlopen(req, context=ssl_context, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
            
            # Extract CVE
            aliases = data.get('aliases', [])
            for alias in aliases:
                if alias.startswith('CVE-'):
                    details['cve'] = alias
                    break
            
            # Extract CVSS
            database_specific = data.get('database_specific', {}) or {}
            cvss_score = None
            severity_label = None
            
            # Database-specific CVSS score
            if 'cvss_score' in database_specific:
                try:
                    cvss_score = float(database_specific['cvss_score'])
                except (TypeError, ValueError):
                    pass
            
            # Database-specific severity label
            db_severity = database_specific.get('severity')
            if isinstance(db_severity, str):
                severity_label = db_severity.upper()
            elif isinstance(db_severity, (int, float)) and cvss_score is None:
                cvss_score = float(db_severity)
            
            # OSV severity array
            severity_entries = data.get('severity')
            if severity_entries:
                if isinstance(severity_entries, list):
                    for entry in severity_entries:
                        if isinstance(entry, dict):
                            score_val = entry.get('score')
                            if score_val is not None:
                                if isinstance(score_val, (int, float)):
                                    score_numeric = float(score_val)
                                    if cvss_score is None or score_numeric > cvss_score:
                                        cvss_score = score_numeric
                                else:
                                    score_str = str(score_val).strip()
                                    try:
                                        score_numeric = float(score_str)
                                        if cvss_score is None or score_numeric > cvss_score:
                                            cvss_score = score_numeric
                                    except ValueError:
                                        # Leave severity unchanged; CVSS vector handled later
                                        pass
                            if not severity_label:
                                severity_text = entry.get('severity') or entry.get('type')
                                if isinstance(severity_text, str):
                                    severity_label = severity_text.upper()
                        else:
                            if not severity_label:
                                severity_label = str(entry).upper()
                else:
                    if not severity_label:
                        severity_label = str(severity_entries).upper()
            
            # Apply extracted scores
            if cvss_score is not None:
                details['cvss'] = round(float(cvss_score), 1)
            if severity_label:
                details['severity'] = severity_label
            
            # Extract description (prefer details over summary)
            details['description'] = data.get('details', '') or data.get('summary', '')
            
            # Extract fixed versions from affected ranges (may have multiple)
            affected = data.get('affected', [])
            fixed_versions = []
            for aff in affected:
                ranges = aff.get('ranges', [])
                for range_info in ranges:
                    events = range_info.get('events', [])
                    for event in events:
                        if 'fixed' in event:
                            fixed_ver = event['fixed']
                            if fixed_ver and fixed_ver not in fixed_versions:
                                fixed_versions.append(fixed_ver)
            
            # Use the highest version as fixed_version (or first if can't compare)
            if fixed_versions:
                # Try to sort versions (simple string comparison for now)
                fixed_versions.sort(reverse=True)
                details['fixed_version'] = fixed_versions[0]
                details['all_fixed_versions'] = fixed_versions
        
        # Fallback to NVD if CVE exists but OSV lacks CVSS/Severity
        severity_value = details.get('severity')
        needs_severity = severity_value is None or (isinstance(severity_value, str) and severity_value.upper().startswith('CVSS:'))
        if details['cve'] and (details['cvss'] is None or needs_severity):
            nvd_details = _fetch_nvd_details(details['cve'])
            if details['cvss'] is None and nvd_details.get('cvss') is not None:
                details['cvss'] = nvd_details['cvss']
            if needs_severity and nvd_details.get('severity'):
                details['severity'] = nvd_details['severity']
            
    except Exception as e:
        # API 호출 실패 시 무시 (기존 정보만 사용)
        pass
    
    return details


def _build_dependency_type_map(
    sbom_data: Optional[Dict[str, Any]],
    repo_name: str,
    project_type: str = 'npm'
) -> Dict[str, Dict[Any, str]]:
    """
    Build a mapping of component name -> dependency_type ('direct' or 'transitive')
    using CycloneDX dependencies section.
    """
    if not sbom_data:
        return {'by_ref': {}, 'by_name_version': {}}
    
    components = sbom_data.get('components', [])
    dependencies = sbom_data.get('dependencies', [])
    
    if not components or not dependencies:
        return {'by_ref': {}, 'by_name_version': {}}
    
    name_by_ref: Dict[str, str] = {}
    for comp in components:
        ref = comp.get('bom-ref')
        name = comp.get('name')
        if ref and name:
            name_by_ref[ref] = name
    
    # Determine root dependency entry (matches repo name if possible)
    root_entry = None
    repo_lower = repo_name.lower()
    for entry in dependencies:
        ref = entry.get('ref', '')
        comp_name = name_by_ref.get(ref, '')
        if comp_name and repo_lower in comp_name.lower():
            root_entry = entry
            break
    
    direct_refs: set[str] = set()
    if root_entry:
        direct_refs.update(root_entry.get('dependsOn', []) or [])
    else:
        # Fallback: components whose dependency entry has no parent
        child_refs = set()
        for entry in dependencies:
            child_refs.update(entry.get('dependsOn', []) or [])
        for entry in dependencies:
            ref = entry.get('ref')
            if ref and ref not in child_refs:
                direct_refs.add(ref)
    
    dep_type_by_ref: Dict[str, str] = {}
    dep_type_by_name_version: Dict[tuple[str, str], str] = {}
    for comp in components:
        ref = comp.get('bom-ref')
        name = comp.get('name')
        if not name or not ref:
            continue
        version = comp.get('version', '')
        key = (name.lower(), version)
        dep_type = 'direct' if ref in direct_refs else 'transitive'
        if project_type == 'golang' and name in {'go', 'toolchain'}:
            dep_type = 'stdlib'
        dep_type_by_ref[ref] = dep_type
        dep_type_by_name_version[key] = dep_type
    
    if project_type == 'golang':
        for comp in components:
            name = comp.get('name', '')
            if name and name.startswith('stdlib'):
                ref = comp.get('bom-ref', '')
                version = comp.get('version', '')
                if ref:
                    dep_type_by_ref[ref] = 'stdlib'
                dep_type_by_name_version[(name.lower(), version)] = 'stdlib'
    
    return {
        'by_ref': dep_type_by_ref,
        'by_name_version': dep_type_by_name_version
    }


def _determine_dependency_type(component: Dict[str, Any], project_type: str = 'npm') -> str:
    """
    Determine if a component is direct or transitive dependency
    
    Args:
        component: SBOM component dictionary
        project_type: 'npm' or 'golang'
        
    Returns:
        'direct' or 'transitive'
    """
    if project_type == 'npm':
        properties = component.get('properties', [])
        for prop in properties:
            if prop.get('name') == 'npm:packagePath':
                package_path = prop.get('value', '')
                # Count depth: node_modules/package = depth 1 (direct)
                # node_modules/package/node_modules/package2 = depth 2+ (transitive)
                depth = package_path.count('/node_modules/')
                return 'direct' if depth == 1 else 'transitive'
    elif project_type == 'golang':
        # For Go, check if it's stdlib or external module
        # stdlib modules are typically direct dependencies
        # External modules in go.mod are direct, others are transitive
        name = component.get('name', '')
        if name.startswith('toolchain@') or name.startswith('stdlib'):
            return 'direct'
        # For Go, we can't easily determine direct vs transitive from SBOM alone
        # Default to direct (can be improved with go.mod parsing)
        return 'direct'
    
    # Default to direct if no packagePath
    return 'direct'


def _get_package_version_from_sbom(sbom_data: Dict[str, Any], package_name: str, project_type: str = 'npm') -> Optional[str]:
    """
    Get current version of a package from SBOM
    
    Args:
        sbom_data: SBOM JSON data
        package_name: Package name to search for
        project_type: 'npm' or 'golang'
        
    Returns:
        Version string or None
    """
    components = sbom_data.get('components', [])
    package_name_lower = package_name.lower()
    
    for component in components:
        comp_name = component.get('name', '').lower()
        
        if project_type == 'npm':
            # Handle scoped packages
            if comp_name == package_name_lower or comp_name.endswith(f'/{package_name_lower}'):
                return component.get('version')
        elif project_type == 'golang':
            # For Go, match module name (e.g., "crypto/x509" matches "stdlib" or full module path)
            # Go packages are like "crypto/x509" but modules are like "stdlib" or "github.com/..."
            if comp_name == package_name_lower:
                return component.get('version')
            # Also check if package is part of a module
            # e.g., "crypto/x509" is part of "stdlib" module
            if package_name_lower.startswith(comp_name + '/') or comp_name == 'stdlib':
                # For stdlib packages, check if the package matches
                if comp_name == 'stdlib' and '/' in package_name:
                    return component.get('version')
                elif comp_name in package_name_lower:
                    return component.get('version')
    
    return None


def generate_dashboard_data(
    output_dir: Path, 
    repo_name: str, 
    sbom_result: Optional[Dict[str, Any]], 
    vuln_result: Optional[Dict[str, Any]],
    project_type: Optional[str] = None
) -> Optional[Path]:
    """
    Generate dashboard-ready JSON with all required information
    
    Args:
        output_dir: Output directory path
        repo_name: Repository name
        sbom_result: SBOM analysis result
        vuln_result: Vulnerability analysis result
        
    Returns:
        Path to generated dashboard JSON file, or None if failed
    """
    print("\n" + "=" * 60)
    print("Generating Dashboard Data")
    print("=" * 60)
    
    try:
        # Load SBOM data
        sbom_file = output_dir / f"{repo_name}-sbom.cdx.json"
        sbom_data = None
        if sbom_file.exists():
            with open(sbom_file, 'r', encoding='utf-8') as f:
                sbom_data = json.load(f)
        
        # Load reachability data
        reachability_file = output_dir / f"{repo_name}-reachability.json"
        reachability_data = None
        if reachability_file.exists():
            with open(reachability_file, 'r', encoding='utf-8') as f:
                reachability_data = json.load(f)
        
        if not reachability_data:
            print("Warning: No reachability data found, skipping dashboard generation")
            return None
        
        # Build dashboard data structure
        dashboard_data = {
            "application": {
                "name": repo_name,
                "analysis_timestamp": datetime.now(timezone.utc).isoformat()
            },
            "packages": [],
            "vulnerabilities": []
        }
        
        # Detect project type from reachability data if not provided
        if not project_type:
            # Check if it's Go or npm based on vulnerability structure
            if reachability_data.get('vulnerabilities'):
                first_vuln = reachability_data['vulnerabilities'][0]
                if 'module' in first_vuln or 'found_in' in first_vuln:
                    project_type = 'golang'
                else:
                    project_type = 'npm'
            else:
                project_type = 'npm'  # Default
        
        # Process packages from SBOM
        dep_type_map = {}
        if sbom_data:
            dep_type_map = _build_dependency_type_map(sbom_data, repo_name, project_type)
            dep_type_by_ref = dep_type_map.get('by_ref', {})
            dep_type_by_name_version = dep_type_map.get('by_name_version', {})
            components = sbom_data.get('components', [])
            repo_lower = (repo_name or '').lower()
            for component in components:
                package_info = {
                    "name": component.get('name', ''),
                    "version": component.get('version', ''),
                    "type": component.get('type', 'library'),
                    "dependency_type": None
                }
                name_lower = (package_info['name'] or '').lower()
                is_main_component = False
                if package_info['type'] == 'application':
                    is_main_component = True
                elif project_type == 'golang' and repo_lower and name_lower and repo_lower in name_lower:
                    is_main_component = True
                if is_main_component:
                    package_info['type'] = 'application'
                    package_info['dependency_type'] = 'application'
                    licenses = component.get('licenses') or []
                    license_ids = []
                    for lic in licenses:
                        if isinstance(lic, dict):
                            lic_info = lic.get('license') if isinstance(lic.get('license'), dict) else lic.get('license')
                            if isinstance(lic_info, dict):
                                if lic_info.get('id'):
                                    license_ids.append(lic_info['id'])
                                elif lic_info.get('name'):
                                    license_ids.append(lic_info['name'])
                            elif isinstance(lic_info, str):
                                license_ids.append(lic_info)
                    if license_ids:
                        package_info['license'] = license_ids[0]
                        package_info['licenses'] = license_ids
                    dashboard_data['packages'].append(package_info)
                    continue
                ref = component.get('bom-ref', '')
                key = (package_info['name'].lower() if package_info['name'] else '', package_info['version'] or '')
                dep_type = None
                if dep_type_by_ref or dep_type_by_name_version:
                    if ref and ref in dep_type_by_ref:
                        dep_type = dep_type_by_ref[ref]
                    elif package_info['name'] and key in dep_type_by_name_version:
                        dep_type = dep_type_by_name_version[key]
                if dep_type is None:
                    dep_type = _determine_dependency_type(component, project_type)
                if project_type == 'golang' and package_info['name'] in {'go', 'toolchain'}:
                    package_info['dependency_type'] = 'stdlib'
                else:
                    package_info['dependency_type'] = dep_type
                
                # Add license information if available
                licenses = component.get('licenses') or []
                license_ids = []
                for lic in licenses:
                    if isinstance(lic, dict):
                        lic_info = lic.get('license') if isinstance(lic.get('license'), dict) else lic.get('license')
                        if isinstance(lic_info, dict):
                            if lic_info.get('id'):
                                license_ids.append(lic_info['id'])
                            elif lic_info.get('name'):
                                license_ids.append(lic_info['name'])
                        elif isinstance(lic_info, str):
                            license_ids.append(lic_info)
                if license_ids:
                    package_info['license'] = license_ids[0]
                    package_info['licenses'] = license_ids

                # Add PURL if available
                purl = component.get('purl', '')
                if purl:
                    package_info['purl'] = purl
                
                dashboard_data['packages'].append(package_info)
        
        # Process vulnerabilities (group by vulnerability ID + package)
        vulnerabilities = reachability_data.get('vulnerabilities', [])
        vuln_entries: List[Dict[str, Any]] = []
        vuln_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
        
        package_dep_lookup: Dict[str, str] = {}
        if project_type == 'golang':
            package_dep_lookup = {
                pkg["name"]: pkg.get("dependency_type")
                for pkg in dashboard_data['packages']
                if pkg.get("name")
            }
        
        for vuln in vulnerabilities:
            if project_type == 'golang':
                package_name = vuln.get('package', '')
                module_name = vuln.get('module', '')
                vuln_id = vuln.get('id', '')
                advisory_url = vuln.get('link', '')
                found_in = vuln.get('found_in', '')
                fixed_in = vuln.get('fixed_in', '')
                
                current_version = None
                if found_in and '@' in found_in:
                    current_version = found_in.split('@')[-1]
                
                fixed_version = None
                if fixed_in and '@' in fixed_in:
                    fixed_version = fixed_in.split('@')[-1]
                
                advisory_details: Dict[str, Any] = {}
                if vuln_id.startswith('GO-'):
                    advisory_details = _fetch_advisory_details(vuln_id)
                
                advisory_fixed_version = advisory_details.get('fixed_version')
                if advisory_fixed_version and not fixed_version:
                    fixed_version = advisory_fixed_version
                
                all_fixed_versions = advisory_details.get('all_fixed_versions', []) or []
                if not all_fixed_versions and fixed_version:
                    all_fixed_versions = [fixed_version]
                
                dep_type = package_dep_lookup.get(module_name) or package_dep_lookup.get(package_name)
                if not dep_type:
                    if module_name == "stdlib" or package_name in {"go", "toolchain"}:
                        dep_type = "stdlib"
                    else:
                        dep_type = "transitive"
                
                key = (vuln_id or "", module_name or package_name or "")
                if key not in vuln_map:
                    base_entry = {
                        "package": {
                            "name": package_name,
                            "module": module_name,
                            "current_version": current_version,
                            "fixed_version": fixed_version,
                            "all_fixed_versions": list(dict.fromkeys(all_fixed_versions)),
                            "affected_range": f"{found_in} -> {fixed_in}" if found_in and fixed_in else "",
                            "dependency_type": dep_type
                        },
                        "vulnerability": {
                            "id": vuln_id,
                            "cve": advisory_details.get('cve'),
                            "cvss": advisory_details.get('cvss'),
                            "severity": advisory_details.get('severity'),
                            "title": vuln.get('title', ''),
                            "description": advisory_details.get('description') or vuln.get('title', ''),
                            "reference_url": advisory_url
                        },
                        "functions": [],
                        "reachable": False,
                        "functions_count": 0,
                        "reachable_functions": 0,
                        "unreachable_functions": 0
                    }
                    vuln_map[key] = base_entry
                    vuln_entries.append(base_entry)
                else:
                    base_entry = vuln_map[key]
                    pkg_info = base_entry["package"]
                    if module_name and not pkg_info.get("module"):
                        pkg_info["module"] = module_name
                    if fixed_version and not pkg_info.get("fixed_version"):
                        pkg_info["fixed_version"] = fixed_version
                    if all_fixed_versions:
                        existing = set(pkg_info.get("all_fixed_versions", []))
                        for ver in all_fixed_versions:
                            if ver and ver not in existing:
                                pkg_info.setdefault("all_fixed_versions", []).append(ver)
                                existing.add(ver)
                
                vuln_funcs = vuln.get('vulnerable_functions', [])
                for func in vuln_funcs:
                    func_name = func.get('function', '')
                    is_reachable = func.get('reachable', False)
                    reaching_entries = func.get('reaching_entry_points', []) or []
                    if reaching_entries:
                        is_reachable = True
                    
                    all_paths: List[List[Dict[str, Any]]] = []
                    entry_point_data: Dict[str, Any] = {}
                    
                    if reaching_entries:
                        for entry_info in reaching_entries:
                            path = entry_info.get('path', [])
                            call_chain = []
                            for step in path:
                                file_path = step.get('file', '')
                                if not file_path:
                                    call_site_files = step.get('call_site_files', [])
                                    if call_site_files:
                                        project_files = [f for f in call_site_files if not f.startswith('/opt/') and not f.startswith('/usr/')]
                                        if project_files:
                                            file_path = project_files[0]
                                        else:
                                            file_path = call_site_files[0]
                                call_chain.append({
                                    "function": step.get('function', ''),
                                    "file": file_path,
                                    "package": step.get('package', ''),
                                    "module": step.get('module', ''),
                                    "call_site_files": step.get('call_site_files', [])
                                })
                            all_paths.append(call_chain)
                        
                        entry_func = reaching_entries[0].get('entry_function', {})
                        entry_file = entry_func.get('file', '')
                        if not entry_file:
                            call_site_files = entry_func.get('call_site_files', [])
                            if call_site_files:
                                project_files = [f for f in call_site_files if not f.startswith('/opt/') and not f.startswith('/usr/')]
                                if project_files:
                                    entry_file = project_files[0]
                                else:
                                    entry_file = call_site_files[0]
                        entry_point_data = {
                            "function": entry_func.get('function', ''),
                            "file": entry_file,
                            "package": entry_func.get('package', ''),
                            "module": entry_func.get('module', '')
                        }
                    
                    function_entry = {
                        "name": func_name,
                        "reachable": bool(is_reachable or all_paths),
                        "total_entry_points": func.get('total_entry_points'),
                        "checked_entry_points": func.get('checked_entry_points'),
                        "reaching_entry_points_count": len(reaching_entries),
                        "reachability_path": all_paths,
                        "call_path": all_paths,
                        "entry_point": entry_point_data
                    }
                    
                    base_entry["functions"].append(function_entry)
                    base_entry["functions_count"] += 1
                    if function_entry["reachable"]:
                        base_entry["reachable_functions"] += 1
                        base_entry["reachable"] = True
                    base_entry["unreachable_functions"] = base_entry["functions_count"] - base_entry["reachable_functions"]
            
            else:
                package_name = vuln.get('package', '')
                vuln_id = vuln.get('vuln_id', '')
                advisory_url = vuln.get('url', '')
                
                advisory_id = vuln_id
                if not (vuln_id.startswith('GHSA-') or vuln_id.startswith('CVE-')):
                    if '/GHSA-' in advisory_url:
                        ghsa_match = re.search(r'GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}', advisory_url, re.IGNORECASE)
                        if ghsa_match:
                            advisory_id = ghsa_match.group(0)
                    elif '/CVE-' in advisory_url:
                        cve_match = re.search(r'CVE-\d{4}-\d{4,7}', advisory_url, re.IGNORECASE)
                        if cve_match:
                            advisory_id = cve_match.group(0)
                
                # Use vulnerability information from reachability.json if available
                # These fields are populated by the parser from OSV.dev API
                vuln_cve = vuln.get('cve') or None
                vuln_cvss = vuln.get('cvss') or None
                vuln_severity = vuln.get('severity', '')
                vuln_title = vuln.get('title', '') or vuln.get('vuln_title', '')
                vuln_description = vuln.get('description', '') or vuln.get('vuln_title', '')
                
                # Try to fetch additional details if not already in reachability data
                advisory_details = {}
                if not vuln_cve or not vuln_cvss or not vuln_severity or vuln_severity == 'unknown':
                    advisory_details = _fetch_advisory_details(advisory_id)
                
                current_version = _get_package_version_from_sbom(sbom_data, package_name, project_type) if sbom_data else None
                
                # Extract CVSS score properly
                cvss_score = None
                if isinstance(vuln_cvss, dict):
                    cvss_score = vuln_cvss.get('score')
                elif isinstance(vuln_cvss, (int, float)):
                    cvss_score = vuln_cvss
                elif vuln_cvss:
                    cvss_score = vuln_cvss
                
                # Fallback to advisory_details if not in reachability data
                if cvss_score is None:
                    cvss_score = advisory_details.get('cvss') or advisory_details.get('cvss_score')
                
                key = (vuln_id or advisory_id or "", package_name or "")
                if key not in vuln_map:
                    base_entry = {
                        "package": {
                            "name": package_name,
                            "current_version": current_version,
                            "fixed_version": advisory_details.get('fixed_version'),
                            "all_fixed_versions": list(dict.fromkeys(advisory_details.get('all_fixed_versions', []) or [])),
                            "affected_range": vuln.get('affected_range', ''),
                            "dependency_type": None  # Will be filled from SBOM
                        },
                        "vulnerability": {
                            "id": vuln_id or advisory_id,
                            "cve": vuln_cve or advisory_details.get('cve'),
                            "cvss": cvss_score if cvss_score is not None else None,
                            "severity": vuln_severity if vuln_severity != 'unknown' else (advisory_details.get('severity') or 'UNKNOWN'),
                            "title": vuln_title or advisory_details.get('title', ''),
                            "description": vuln_description or advisory_details.get('description', ''),
                            "reference_url": advisory_url
                        },
                        "functions": [],
                        "reachable": False,
                        "functions_count": 0,
                        "reachable_functions": 0,
                        "unreachable_functions": 0
                    }
                    vuln_map[key] = base_entry
                    vuln_entries.append(base_entry)
                else:
                    base_entry = vuln_map[key]
                    pkg_info = base_entry["package"]
                    if current_version and not pkg_info.get("current_version"):
                        pkg_info["current_version"] = current_version
                    fixed_version = advisory_details.get('fixed_version')
                    if fixed_version and not pkg_info.get("fixed_version"):
                        pkg_info["fixed_version"] = fixed_version
                    fixed_versions = advisory_details.get('all_fixed_versions', []) or []
                    if fixed_versions:
                        existing = set(pkg_info.get("all_fixed_versions", []))
                        for ver in fixed_versions:
                            if ver and ver not in existing:
                                pkg_info.setdefault("all_fixed_versions", []).append(ver)
                                existing.add(ver)
                
                vuln_funcs = vuln.get('vulnerable_functions', [])
                for func in vuln_funcs:
                    func_name = func.get('vulnerable_function')
                    is_reachable = func.get('reachable', False)
                    reaching_entries = func.get('reaching_entry_points', []) or []
                    if reaching_entries:
                        is_reachable = True
                    
                    all_paths: List[List[Dict[str, Any]]] = []
                    entry_point_data: Dict[str, Any] = {}
                    
                    if reaching_entries:
                        for entry_info in reaching_entries:
                            path = entry_info.get('path', [])
                            call_chain = []
                            for step in path:
                                call_chain.append({
                                    "function": step.get('function', ''),
                                    "file": step.get('file', ''),
                                    "package": step.get('package', '')
                                })
                            all_paths.append(call_chain)
                        
                        entry_func = reaching_entries[0].get('entry_function', {})
                        entry_point_data = {
                            "function": entry_func.get('function', ''),
                            "file": entry_func.get('file', ''),
                            "package": entry_func.get('package', '')
                        }
                    
                    function_entry = {
                        "name": func_name,
                        "reachable": bool(is_reachable or all_paths),
                        "total_entry_points": func.get('total_entry_points'),
                        "checked_entry_points": func.get('checked_entry_points'),
                        "reaching_entry_points_count": len(reaching_entries),
                        "reachability_path": all_paths,
                        "call_path": all_paths,
                        "entry_point": entry_point_data
                    }
                    
                    if sbom_data and not vuln_map[key]["package"].get("dependency_type"):
                        for pkg in dashboard_data['packages']:
                            if pkg['name'].lower() == package_name.lower():
                                vuln_map[key]["package"]["dependency_type"] = pkg['dependency_type']
                                break
                    
                    base_entry = vuln_map[key]
                    base_entry["functions"].append(function_entry)
                    base_entry["functions_count"] += 1
                    if function_entry["reachable"]:
                        base_entry["reachable_functions"] += 1
                        base_entry["reachable"] = True
                    base_entry["unreachable_functions"] = base_entry["functions_count"] - base_entry["reachable_functions"]
        
        dashboard_data['vulnerabilities'] = vuln_entries
        
        # Save dashboard data
        dashboard_file = output_dir / f"{repo_name}-dashboard.json"
        with open(dashboard_file, 'w', encoding='utf-8') as f:
            json.dump(dashboard_data, f, indent=2, ensure_ascii=False)
        
        print(f"Dashboard data generated: {dashboard_file.name}")
        print(f"  - Packages: {len(dashboard_data['packages'])}")
        print(f"  - Vulnerabilities: {len(dashboard_data['vulnerabilities'])}")
        
        return dashboard_file
        
    except Exception as e:
        print(f"Error generating dashboard data: {e}")
        import traceback
        traceback.print_exc()
        return None


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Bomtori - Integrated SBOM and SCA Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py https://github.com/user/repo.git
  python main.py https://github.com/user/repo.git --output-dir ./results
        """
    )
    
    parser.add_argument(
        "github_url",
        nargs="?",
        help="GitHub repository URL to analyze"
    )
    
    parser.add_argument(
        "--output-dir", "-o",
        default="./output",
        help="Output directory for results (default: ./output)"
    )
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Get GitHub URL from argument or user input
    if args.github_url:
        github_url = args.github_url
    else:
        github_url = input("Enter GitHub repository URL to analyze: ").strip()
    
    if not github_url:
        print("Error: GitHub URL is required")
        sys.exit(1)
    
    # Create output directory (자동 권한 처리)
    output_dir = Path(args.output_dir)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except FileExistsError:
        # 파일이 존재하면 삭제 후 디렉터리 생성
        if output_dir.is_file():
            output_dir.unlink()
            output_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError as e:
        print(f"[Bomtori] Warning: output_dir permission issue: {e}. Trying to fix with chmod 777...")
        try:
            import subprocess
            subprocess.run(["chmod", "-R", "777", str(output_dir)], check=False)
            output_dir.mkdir(parents=True, exist_ok=True)
            print("[Bomtori] output_dir permission fixed.")
        except Exception as e2:
            print(f"[Bomtori] Failed to fix output_dir permission automatically: {e2}")
            raise
    
    # Extract repository name
    repo_name = github_url.split('/')[-1].replace('.git', '')
    source_dir = output_dir / repo_name
    
    print(f"Project: {repo_name}")
    print(f"Output directory: {output_dir}")
    print(f"GitHub URL: {github_url}")
    print()
    
    # Clone repository
    if clone_repository(github_url, source_dir):
        source_dir = source_dir.resolve()
    else:
        print("Failed to clone repository")
        sys.exit(1)
    
    try:
        # Detect project type
        print("\nDetecting project type...")
        base_analyzer = BaseAnalyzer(str(source_dir))
        project_type = base_analyzer.get_project_type()
        
        if project_type == ProjectType.UNKNOWN:
            print(f"Error: Could not detect project type")
            print("   Supported types: golang, npm")
            sys.exit(1)
        
        print(f"Project type: {project_type.value}")
        
        # Run SBOM analysis
        sbom_result = run_sbom_analysis(source_dir, output_dir, project_type, github_url, repo_name)
        
        # Run SCA analysis
        sca_result = run_sca_analysis(source_dir, output_dir, project_type, repo_name)
        
        # Run Vulnerability analysis (for Go and NPM projects)
        vuln_result = None
        if project_type == ProjectType.GOLANG or project_type == ProjectType.NPM:
            vuln_result = run_vulnerability_analysis(source_dir, output_dir, repo_name, project_type)
        
        # Generate summary report - use repo_name for all files
        generate_summary_report(output_dir, repo_name, sbom_result, sca_result, vuln_result)
        
        # Generate dashboard data
        # dashboard.json은 reachability.json 파일이 있으면 생성 가능
        # vuln_result가 None이어도 reachability.json 파일이 있으면 생성 시도
        reachability_file = output_dir / f"{repo_name}-reachability.json"
        if reachability_file.exists() or vuln_result:
            generate_dashboard_data(output_dir, repo_name, sbom_result, vuln_result, project_type.value)
        
        # Clean up unnecessary files after dashboard.json generation
        # callGraph.json만 삭제 (매우 큰 파일이므로 디스크 공간 절약 및 Git 제한 회피)
        print("\n" + "=" * 60)
        print("Cleaning up unnecessary files...")
        print("=" * 60)
        
        files_to_remove = [
            f"{repo_name}-callGraph.json"
        ]
        
        removed_count = 0
        for filename in files_to_remove:
            file_path = output_dir / filename
            if file_path.exists():
                try:
                    file_size = file_path.stat().st_size / (1024 * 1024)  # MB
                    file_path.unlink()
                    removed_count += 1
                    print(f"  ✓ Removed: {filename} ({file_size:.2f} MB)")
                except Exception as e:
                    print(f"  ✗ Failed to remove {filename}: {e}")
        
        if removed_count > 0:
            print(f"\nCleaned up {removed_count} unnecessary file(s)")
        else:
            print("No unnecessary files to clean up")
        
        print("\n" + "=" * 60)
        print("All analyses completed successfully!")
        print("=" * 60)
        print(f"\nResults location: {output_dir}")
        print("\nGenerated files:")
        for file in sorted(output_dir.glob(f"{repo_name}*")):
            print(f"  - {file.name}")
        
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        # Clean up cloned repository
        if source_dir.exists() and source_dir.is_dir():
            try:
                print(f"\nCleaning up temporary directory...")
                shutil.rmtree(source_dir)
                print(f"Temporary directory cleaned up")
            except Exception as e:
                print(f"Warning: Failed to clean up temporary directory: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error occurred: {e}")
        import traceback
        traceback.print_exc()
        # Clean up cloned repository
        if source_dir.exists() and source_dir.is_dir():
            try:
                print(f"\nCleaning up temporary directory...")
                shutil.rmtree(source_dir)
                print(f"Temporary directory cleaned up")
            except Exception as e:
                print(f"Warning: Failed to clean up temporary directory: {e}")
        sys.exit(1)
    
    # Clean up cloned repository after successful analysis
    if source_dir.exists() and source_dir.is_dir():
        try:
            print(f"\nCleaning up temporary directory...")
            shutil.rmtree(source_dir)
            print(f"Temporary directory cleaned up")
        except Exception as e:
            print(f"Warning: Failed to clean up temporary directory: {e}")


if __name__ == "__main__":
    main()
