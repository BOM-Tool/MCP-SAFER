#!/usr/bin/env python3
"""
TypeScript/npm vulnerability reachability analysis module
Combines npm audit, GitHub Advisory API, commit diff parsing, and call graph analysis
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional

from .parser import NpmAuditParser
from .callgraph import TypeScriptCallGraphLoader
from .reachability import TypeScriptReachabilityAnalyzer


def run_vulnerability_analysis(
    callgraph_file: str,
    audit_file: str,
    project_path: Optional[str] = None,
    output_file: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Run vulnerability reachability analysis for TypeScript/npm projects
    
    This function:
    1. Parses npm audit.json to get vulnerability list
    2. Fetches detailed info from GitHub Advisory API
    3. Extracts vulnerable functions from Advisory description and commit diffs
    4. Loads TypeScript call graph
    5. Analyzes reachability from entry points to vulnerable functions
    
    Args:
        callgraph_file: TypeScript Call Graph JSON file path
        audit_file: npm audit.json file path
        project_path: Project root path (optional, auto-detected from audit_file)
        output_file: Output JSON file path (auto-generated if None)
    
    Returns:
        Analysis result dictionary or None on failure
    """
    callgraph_file = str(Path(callgraph_file).expanduser().resolve())
    audit_file = str(Path(audit_file).expanduser().resolve())
    
    if not Path(callgraph_file).exists():
        print(f"Error: Call Graph file not found: {callgraph_file}")
        return None
    
    if not Path(audit_file).exists():
        print(f"Error: npm audit file not found: {audit_file}")
        return None
    
    # Auto-generate output filename
    if not output_file:
        callgraph_path = Path(callgraph_file)
        output_file = str(callgraph_path.parent / f"{callgraph_path.stem.replace('-callGraph', '')}-reachability.json")
    output_file = str(Path(output_file).expanduser().resolve())
    
    # Try to infer project_path from audit_file if not provided
    if not project_path:
        audit_path = Path(audit_file)
        for parent in [audit_path.parent, audit_path.parent.parent]:
            if (parent / 'package.json').exists():
                project_path = str(parent)
                break
    
    print("\n" + "=" * 70)
    print("npm/TypeScript Vulnerability Reachability Analysis")
    print("=" * 70)
    
    # Step 1: Parse npm audit and extract vulnerable functions
    print(f"\n[1] Parsing npm audit results: {audit_file}")
    parser = NpmAuditParser(audit_file, project_path=project_path)
    vulnerabilities = parser.parse()
    print(f"   Parsed {len(vulnerabilities)} vulnerabilities")
    
    vulns_with_functions = [v for v in vulnerabilities if v.get('vulnerable_functions')]
    print(f"   - With function information: {len(vulns_with_functions)}")
    print(f"   - Without function information: {len(vulnerabilities) - len(vulns_with_functions)}")
    
    for vuln in vulnerabilities:
        funcs = vuln.get('vulnerable_functions', [])
        if funcs:
            print(f"   [{vuln['package']}] {len(funcs)} vulnerable functions: {', '.join(funcs[:3])}{'...' if len(funcs) > 3 else ''}")
    
    # Step 2: Load call graph
    print(f"\n[2] Loading TypeScript Call Graph: {callgraph_file}")
    callgraph_loader = TypeScriptCallGraphLoader(callgraph_file)
    if not callgraph_loader.load():
        print("   Call Graph loading failed")
        return None
    
    print(f"   Graph nodes: {len(callgraph_loader.graph)}")
    print(f"   File mappings: {len(callgraph_loader.file_to_functions)}")
    print(f"   Imported packages: {len(callgraph_loader.imported_packages)}")
    
    # Step 3: Analyze reachability
    print(f"\n[3] Analyzing reachability from entry points...")
    analyzer = TypeScriptReachabilityAnalyzer(callgraph_loader)
    
    all_entry_points = analyzer.get_all_entry_points(only_main=True)
    print(f"   Total main entry points: {len(all_entry_points)}")
    
    if all_entry_points:
        print(f"   Entry points (first 5):")
        for ep in all_entry_points[:5]:
            print(f"      - {ep['function']}")
    
    vuln_analysis_results = []
    total_reachable_funcs = 0
    
    for vuln in vulnerabilities:
        vuln_results = {
            'vuln_id': vuln['id'],
            'vuln_title': vuln.get('title', ''),
            'package': vuln['package'],
            'severity': vuln.get('severity', 'unknown'),
            'url': vuln.get('url', ''),
            'affected_range': vuln.get('affected_range', ''),
            'vulnerable_functions': []
        }
        
        # Add CVE and CVSS if available
        if vuln.get('cve'):
            vuln_results['cve'] = vuln['cve']
        if vuln.get('cvss'):
            vuln_results['cvss'] = vuln['cvss']
        if vuln.get('description'):
            vuln_results['description'] = vuln['description']
        
        vulnerable_functions = vuln.get('vulnerable_functions', [])
        
        if not vulnerable_functions:
            print(f"\n   [{vuln['package']}] Warning: No vulnerable functions extracted")
            vuln_results['vulnerable_functions'].append({
                'vulnerable_function': None,
                'vulnerable_function_pattern': None,
                'vulnerable_function_info': None,
                'reachable': False,
                'total_entry_points': len(all_entry_points),
                'checked_entry_points': 0,
                'reaching_entry_points': [],
                'unreachable_count': 0,
                'reason': 'No vulnerable function information available'
            })
        else:
            print(f"\n   [{vuln['package']}] Analyzing {len(vulnerable_functions)} vulnerable function(s)...")
            
            for vuln_func in vulnerable_functions:
                print(f"      Analyzing: {vuln_func}...")
                # 개선: 메인 프로젝트 내부 함수를 우선적으로 확인 (사용자가 원하는 것)
                # 1단계: 프로젝트 내부 함수 확인 ([top-level] 제외)
                result = analyzer.analyze_vulnerable_function_from_all_entries(
                    vuln_func,
                    package_name=vuln['package'],
                    max_entry_points=100,  # 성능을 위해 제한 (경로를 찾으면 즉시 중단)
                    max_depth=50,
                    only_main=False  # 프로젝트 내부 함수 확인 ([top-level] 제외)
                )
                
                # # 프로젝트 내부 함수에서 찾지 못했고, 패키지가 사용되는 경우에만 [top-level] 확인
                # if not result.get('reachable', False) and result.get('vulnerable_function_info'):
                #     # [top-level] 진입점도 확인 (fallback)
                #     print(f"         Not found in project functions, checking [top-level] entry points...")
                #     # 성능 최적화: [top-level] 진입점만 제한적으로 확인
                #     result_extended = analyzer.analyze_vulnerable_function_from_all_entries(
                #         vuln_func,
                #         package_name=vuln['package'],
                #         max_entry_points=500,  # [top-level]은 더 많이 확인 가능
                #         max_depth=50,
                #         only_main=True  # [top-level] 진입점만 확인
                #     )
                #     # 더 나은 결과 사용 (reachable이면)
                #     if result_extended.get('reachable', False):
                #         result = result_extended
                
                mapped_funcs = result.get('call_graph_functions', [])
                reason = result.get('reason', '')
                
                if mapped_funcs:
                    print(f"         Call Graph mapping: {len(mapped_funcs)} function(s) found")
                    for mapped in mapped_funcs[:3]:
                        print(f"            - {mapped['function']}")
                    
                    if result.get('reachable', False):
                        reaching_entries = result.get('reaching_entry_points', [])
                        print(f"         REACHABLE from {len(reaching_entries)} entry point(s)")
                        total_reachable_funcs += 1
                    else:
                        print(f"         UNREACHABLE")
                elif result.get('reachable', False):
                    # Package-level analysis found reachability
                    reaching_entries = result.get('reaching_entry_points', [])
                    print(f"         POTENTIALLY REACHABLE (package-level analysis)")
                    print(f"            - Package: {vuln['package']}")
                    print(f"            - Reaching from {len(reaching_entries)} entry point(s)")
                    total_reachable_funcs += 1
                else:
                    print(f"         Warning: No functions mapped in Call Graph")
                    if reason:
                        print(f"            - Reason: {reason}")
                
                vuln_results['vulnerable_functions'].append(result)
        
        vuln_analysis_results.append(vuln_results)
    
    # Create summary
    summary = {
        'total_vulnerabilities': len(vulnerabilities),
        'vulnerabilities_with_functions': len(vulns_with_functions),
        'total_entry_points': len(all_entry_points),
        'total_reachable_functions': total_reachable_funcs,
    }
    
    result = {
        'summary': summary,
        'vulnerabilities': vuln_analysis_results,
    }
    
    # Save results
    print(f"\n[4] Saving results to: {output_file}")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    
    print(f"\nAnalysis complete!")
    print(f"   Total vulnerabilities: {len(vulnerabilities)}")
    print(f"   Vulnerabilities with functions: {len(vulns_with_functions)}")
    print(f"   Reachable functions: {total_reachable_funcs}")
    print(f"   Results saved to: {output_file}")
    
    print("\n" + "=" * 70)
    print("Summary:")
    print(f"  Total vulnerabilities: {len(vulnerabilities)}")
    print(f"  With function info: {len(vulns_with_functions)}")
    print(f"  Reachable functions: {total_reachable_funcs}")
    print("=" * 70)
    
    return result
