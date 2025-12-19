#!/usr/bin/env python3
"""
Vulnerability reachability analysis module
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional

from .parser import VulnCheckParser
from .callgraph import CallGraphLoader
from .reachability import ReachabilityAnalyzer
from .govulncheck import GovulnCheckRunner


def run_vulnerability_analysis(
    callgraph_file: str,
    project_path: str,
    output_file: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Run vulnerability reachability analysis
    
    Args:
        callgraph_file: Call Graph JSON file path
        project_path: Go project path (for govulncheck execution)
        output_file: Output JSON file path (auto-generated if None)
    
    Returns:
        Analysis result dictionary or None on failure
    """
    callgraph_file = str(Path(callgraph_file).expanduser().resolve())
    project_path = str(Path(project_path).expanduser().resolve())
    
    if not Path(callgraph_file).exists():
        print(f"Error: Call Graph file not found: {callgraph_file}")
        return None
    
    if not Path(project_path).exists():
        print(f"Error: Project path not found: {project_path}")
        return None
    
    if not output_file:
        callgraph_path = Path(callgraph_file)
        output_file = str(callgraph_path.parent / f"{callgraph_path.stem}-reachability.json")
    output_file = str(Path(output_file).expanduser().resolve())
    
    print(f"\n[0] Running govulncheck...")
    runner = GovulnCheckRunner(project_path)
    if not runner.is_available():
        print(f"   Error: govulncheck not found")
        print(f"   Install: go install golang.org/x/vuln/cmd/govulncheck@latest")
        return None
    
    success, vuln_file = runner.run()
    if not success:
        print(f"   Error: govulncheck execution failed")
        return None
    
    vuln_file = str(Path(vuln_file).expanduser().resolve())
    
    print(f"\n[1] Parsing govulncheck results: {vuln_file}")
    parser = VulnCheckParser(vuln_file)
    vulnerabilities = parser.parse()
    print(f"   Parsed {len(vulnerabilities)} vulnerabilities")
    
    # Separate reachable and unreachable vulnerabilities
    reachable_vulns = [v for v in vulnerabilities if v.get('is_reachable', False)]
    unreachable_vulns = [v for v in vulnerabilities if not v.get('is_reachable', False)]
    
    print(f"   - Reachable (Symbol Results): {len(reachable_vulns)}")
    print(f"   - Unreachable (Package Results): {len(unreachable_vulns)}")
    
    total_vuln_funcs = sum(len(v.get('vulnerable_functions', [])) for v in vulnerabilities)
    print(f"   Extracted {total_vuln_funcs} vulnerable functions")
    
    for vuln in vulnerabilities:
        funcs = vuln.get('vulnerable_functions', [])
        reachable_status = "REACHABLE" if vuln.get('is_reachable', False) else "UNREACHABLE"
        if not funcs:
            if vuln.get('is_reachable', False):
                print(f"   WARNING: [{vuln['id']}] No vulnerable functions extracted (REACHABLE)")
            else:
                print(f"   [{vuln['id']}] {reachable_status}: No vulnerable functions (package-level only)")
        else:
            print(f"   [{vuln['id']}] {reachable_status}: {len(funcs)} vulnerable functions: {', '.join(funcs[:3])}{'...' if len(funcs) > 3 else ''}")
    
    print(f"\n[2] Loading Call Graph: {callgraph_file}")
    callgraph_loader = CallGraphLoader(callgraph_file)
    if not callgraph_loader.load():
        print("   Error: Call Graph loading failed")
        return None
    
    print(f"   Graph nodes: {len(callgraph_loader.graph)}")
    print(f"   File mappings: {len(callgraph_loader.file_to_functions)}")
    
    print(f"\n[3] Analyzing reachability from entry points...")
    analyzer = ReachabilityAnalyzer(callgraph_loader)
    
    all_entry_points = analyzer.get_all_entry_points(only_main=True)
    print(f"   Total main entry points: {len(all_entry_points)}")
    
    vuln_analysis_results = []
    for vuln in vulnerabilities:
        vuln_results = {
            'vuln_id': vuln['id'],
            'vuln_title': vuln['title'],
            'is_reachable': vuln.get('is_reachable', False),
            'vulnerable_functions': []
        }
        
        # If unreachable, create a placeholder result without function analysis
        if not vuln.get('is_reachable', False):
            print(f"   [{vuln['id']}] Unreachable vulnerability (package-level only)")
            # Create unreachable result for consistency
            vuln_results['vulnerable_functions'].append({
                'vulnerable_function': None,
                'vulnerable_function_pattern': None,
                'vulnerable_function_info': None,
                'reachable': False,
                'total_entry_points': len(all_entry_points),
                'checked_entry_points': 0,
                'reaching_entry_points': [],
                'unreachable_count': 0,
                'reason': 'Vulnerability is in package but not called from code'
            })
        else:
            # Analyze reachable vulnerabilities
            for vuln_func in vuln.get('vulnerable_functions', []):
                print(f"   Analyzing: {vuln_func}...")
                result = analyzer.analyze_vulnerable_function_from_all_entries(
                    vuln_func,
                    max_entry_points=None,
                    max_depth=50,
                    only_main=True
                )
                
                mapped_funcs = result.get('call_graph_functions', [])
                if mapped_funcs:
                    print(f"      Call Graph mapping: {len(mapped_funcs)} functions found")
                    for mapped in mapped_funcs[:3]:
                        print(f"         - {mapped['function']}")
                else:
                    print(f"      WARNING: No functions mapped in Call Graph")
                
                vuln_results['vulnerable_functions'].append(result)
        
        vuln_analysis_results.append(vuln_results)
    
    total_reachable_funcs = sum(
        1 for vuln_result in vuln_analysis_results
        for func_result in vuln_result['vulnerable_functions']
        if func_result.get('reachable', False)
    )
    total_reaching_entries = sum(
        len(func_result.get('reaching_entry_points', []))
        for vuln_result in vuln_analysis_results
        for func_result in vuln_result['vulnerable_functions']
    )
    
    print(f"   Reachable functions: {total_reachable_funcs}/{total_vuln_funcs}")
    print(f"   Total reaching entry points: {total_reaching_entries}")
    
    print(f"\n[4] Generating results...")
    output = generate_output_from_functions(vulnerabilities, vuln_analysis_results, len(all_entry_points))
    
    print(f"\n[5] Saving results: {output_file}")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    print("\n" + "=" * 80)
    print("Analysis completed!")
    print("=" * 80)
    print(f"Total vulnerabilities: {output['summary']['total_vulnerabilities']}")
    print(f"  - Reachable vulnerabilities: {output['summary']['reachable_vulnerabilities']}")
    print(f"  - Unreachable vulnerabilities: {output['summary']['unreachable_vulnerabilities']}")
    print(f"Vulnerability reachability rate: {output['summary']['vulnerability_reachability_rate']}")
    print(f"\nTotal entry points: {output['summary']['total_entry_points']}")
    print(f"Total vulnerable functions: {output['summary']['total_vulnerable_functions']}")
    print(f"Reachable functions: {output['summary']['reachable_functions']}")
    print(f"Unreachable functions: {output['summary']['unreachable_functions']}")
    print(f"Function reachability rate: {output['summary']['reachability_rate']}")
    print(f"Total reaching entry points: {output['summary']['total_reaching_entry_points']}")
    print(f"\nResult file: {output_file}")
    
    return output


def generate_output_from_functions(
    vulnerabilities: List[Dict[str, Any]],
    vuln_analysis_results: List[Dict[str, Any]],
    total_entry_points: int
) -> Dict[str, Any]:
    """Generate final JSON output from vulnerable function analysis"""
    
    total_vulnerabilities = len(vulnerabilities)
    reachable_vulns = sum(1 for v in vulnerabilities if v.get('is_reachable', False))
    unreachable_vulns = total_vulnerabilities - reachable_vulns
    
    total_vuln_funcs = sum(len(v.get('vulnerable_functions', [])) for v in vulnerabilities)
    
    reachable_funcs = sum(
        1 for vuln_result in vuln_analysis_results
        for func_result in vuln_result['vulnerable_functions']
        if func_result.get('reachable', False)
    )
    unreachable_funcs = total_vuln_funcs - reachable_funcs
    
    total_reaching_entries = sum(
        len(func_result.get('reaching_entry_points', []))
        for vuln_result in vuln_analysis_results
        for func_result in vuln_result['vulnerable_functions']
    )
    
    output = {
        'summary': {
            'total_vulnerabilities': total_vulnerabilities,
            'reachable_vulnerabilities': reachable_vulns,
            'unreachable_vulnerabilities': unreachable_vulns,
            'total_entry_points': total_entry_points,
            'total_vulnerable_functions': total_vuln_funcs,
            'reachable_functions': reachable_funcs,
            'unreachable_functions': unreachable_funcs,
            'total_reaching_entry_points': total_reaching_entries,
            'reachability_rate': f"{(reachable_funcs/total_vuln_funcs*100):.1f}%" if total_vuln_funcs > 0 else "0%",
            'vulnerability_reachability_rate': f"{(reachable_vulns/total_vulnerabilities*100):.1f}%" if total_vulnerabilities > 0 else "0%"
        },
        'vulnerabilities': []
    }
    
    vuln_result_map = {r['vuln_id']: r for r in vuln_analysis_results}
    
    for vuln in vulnerabilities:
        vuln_id = vuln['id']
        vuln_result = vuln_result_map.get(vuln_id, {})
        
        vuln_output = {
            'id': vuln['id'],
            'title': vuln['title'],
            'link': vuln['link'],
            'package': vuln['package'],
            'module': vuln['module'],
            'found_in': vuln['found_in'],
            'fixed_in': vuln['fixed_in'],
            'is_stdlib': vuln['is_stdlib'],
            'is_reachable': vuln.get('is_reachable', False),
            'vulnerable_functions': []
        }
        
        for func_result in vuln_result.get('vulnerable_functions', []):
            func_output = {
                'function': func_result.get('vulnerable_function', ''),
                'vulnerable_function_info': func_result.get('vulnerable_function_info'),
                'reachable': func_result.get('reachable', False),
                'total_entry_points': func_result.get('total_entry_points', 0),
                'checked_entry_points': func_result.get('checked_entry_points', 0),
                'reaching_entry_points_count': len(func_result.get('reaching_entry_points', [])),
                'reaching_entry_points': func_result.get('reaching_entry_points', []),
                'unreachable_count': func_result.get('unreachable_count', 0),
                'reason': func_result.get('reason')
            }
            
            vuln_output['vulnerable_functions'].append(func_output)
        
        output['vulnerabilities'].append(vuln_output)
    
    return output
