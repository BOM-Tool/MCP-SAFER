#!/usr/bin/env python3
"""
npm audit result parser module
Extracts vulnerable functions from npm audit and GitHub Advisory
"""

import json
import re
from typing import Dict, List, Any, Optional
from pathlib import Path
import urllib.request
import urllib.parse
import urllib.error
import ssl

# Try to import tree-sitter for AST parsing (optional)
try:
    from tree_sitter import Language, Parser
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False


class NpmAuditParser:
    """npm audit.json parser with GitHub Advisory integration"""
    
    def __init__(self, audit_file: str, project_path: Optional[str] = None):
        self.audit_file = Path(audit_file).expanduser().resolve()
        self.project_path = Path(project_path).expanduser().resolve() if project_path else None
        self.vulnerabilities = []
        self.vuln_function_patterns = {}
        self.project_packages = self._load_project_packages()
        self.js_parser = None
        self.ts_parser = None
        self._init_parsers()
    
    def _init_parsers(self):
        """
        Initialize JavaScript and TypeScript parsers if tree-sitter is available.
        
        Requires:
        - pip install tree-sitter
        - pip install tree-sitter-javascript tree-sitter-typescript
        
        If not available, falls back to regex-based extraction.
        """
        if not TREE_SITTER_AVAILABLE:
            return
        
        try:
            # Try to load tree-sitter-javascript
            try:
                import tree_sitter_javascript as tjs
                js_lang = Language(tjs.language())
                self.js_parser = Parser(js_lang)  # Parser 생성자에 Language 직접 전달
            except (ImportError, AttributeError, Exception) as e:
                # tree-sitter-javascript가 설치되지 않았거나 초기화 실패
                # js_parser는 None으로 유지 (regex fallback 사용)
                pass
            
            # Try to load tree-sitter-typescript
            try:
                import tree_sitter_typescript as tts
                # TSX 파서가 TS와 TSX 모두 지원 (더 범용적)
                ts_lang = Language(tts.language_tsx())
                self.ts_parser = Parser(ts_lang)  # Parser 생성자에 Language 직접 전달
            except (ImportError, AttributeError, Exception) as e:
                # tree-sitter-typescript가 설치되지 않았거나 초기화 실패
                # ts_parser는 None으로 유지 (regex fallback 사용)
                pass
        except Exception:
            # Fallback to regex if parser initialization fails
            pass
    
    def _get_parser_for_file(self, file_path: str):
        """
        Get appropriate parser based on file extension.
        Returns: (parser, language_name) tuple or (None, None) if not available
        """
        if not file_path:
            return None, None
        
        file_lower = file_path.lower()
        
        # JavaScript files
        if file_lower.endswith(('.js', '.jsx')):
            return self.js_parser, 'javascript'
        
        # TypeScript files
        elif file_lower.endswith(('.ts', '.tsx')):
            return self.ts_parser, 'typescript'
        
        # Default: try TypeScript first, then JavaScript
        elif self.ts_parser:
            return self.ts_parser, 'typescript'
        elif self.js_parser:
            return self.js_parser, 'javascript'
        
        return None, None
    
    def _convert_pnpm_audit_to_npm_format(self, audit_data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """
        Convert pnpm audit format to npm audit format
        
        pnpm format: {"actions": [{"action": "update", "module": "package", "resolves": [{"id": 123, ...}]}]}
        npm format: {"vulnerabilities": {"package": {"via": [{"name": "GHSA-xxx", ...}]}}}
        
        Note: pnpm uses numeric advisory IDs. We'll try to fetch GHSA ID from OSV.dev API
        using the numeric ID, or use it directly if OSV.dev supports it.
        """
        vulnerabilities = {}
        # audit_data가 리스트일 수도 있으므로 확인
        if isinstance(audit_data, list):
            print("   Warning: pnpm audit data is a list, cannot convert to npm format")
            return {}
        if not isinstance(audit_data, dict):
            print(f"   Warning: pnpm audit data is not a dict or list: {type(audit_data)}")
            return {}
        actions = audit_data.get('actions', [])
        
        for action in actions:
            module = action.get('module', '')
            if not module:
                continue
            
            resolves = action.get('resolves', [])
            if not resolves:
                continue
            
            # Group resolves by module
            if module not in vulnerabilities:
                vulnerabilities[module] = {
                    'via': [],
                    'range': '',
                    'nodes': []
                }
            
            # Convert each resolve to via format
            for resolve in resolves:
                vuln_id = resolve.get('id')
                if not vuln_id:
                    continue
                
                # Extract actual vulnerable package from path
                # Path format: .>package1>package2>vulnerable-package
                # or: apps__name>package1>vulnerable-package
                path = resolve.get('path', '')
                actual_vulnerable_package = module  # Default to module
                
                if path:
                    # Parse path to find the actual vulnerable package
                    # Path is like: ".>@changesets/cli>@changesets/read>@changesets/parse>js-yaml"
                    # The last package in the path is usually the vulnerable one
                    path_parts = [p.strip() for p in path.split('>') if p.strip()]
                    if path_parts:
                        # Remove leading "." or workspace prefix
                        clean_parts = [p for p in path_parts if p and p != '.' and not p.startswith('apps__')]
                        if clean_parts:
                            # Last part is usually the vulnerable package
                            last_part = clean_parts[-1]
                            # Handle scoped packages
                            if '/' in last_part:
                                actual_vulnerable_package = last_part
                            else:
                                actual_vulnerable_package = last_part
                
                # pnpm uses numeric advisory IDs (GitHub Advisory database IDs)
                # We'll use the numeric ID and let the API fetch logic try to resolve it
                # The _extract_vulnerable_functions will try to fetch from OSV.dev/GitHub API
                
                # Create via entry (similar to npm format)
                # Use numeric ID as the identifier - API fetch will try to resolve it
                via_entry = {
                    'name': str(vuln_id),  # Use numeric ID as identifier
                    'source': vuln_id,
                    'dependency': module,
                    'actual_package': actual_vulnerable_package,  # Store actual vulnerable package
                    'title': '',  # Will be fetched from API
                    'url': f'https://osv.dev/vulnerability/{vuln_id}',  # Try OSV.dev with numeric ID
                    'severity': 'unknown',  # Will be fetched from API
                    'cwe': [],
                    'cvss': {}
                }
                
                vulnerabilities[module]['via'].append(via_entry)
        
        return vulnerabilities
    
    def _get_ghsa_id_from_numeric_id(self, numeric_id: int, package_name: str = '') -> Optional[str]:
        """
        Try to get GHSA ID from pnpm's numeric advisory ID
        
        pnpm uses numeric IDs. We can try:
        1. Query OSV.dev API by package name and see if we can find matching GHSA
        2. Use the numeric ID directly if OSV.dev supports it
        
        For now, we'll use the numeric ID as-is and let the API fetch logic handle it.
        The _extract_advisory_id and _fetch_from_advisory_api methods will try to resolve it.
        """
        # pnpm numeric IDs are GitHub Advisory database IDs
        # We can try to construct a potential GHSA URL or let API fetch handle it
        # For now, return None to use the numeric ID directly
        return None
    
    def parse(self) -> List[Dict[str, Any]]:
        """Parse npm/pnpm audit.json and extract vulnerability information"""
        if not self.audit_file.exists():
            raise FileNotFoundError(f"File not found: {self.audit_file}")
        
        print(f"[SCA:VULN] Parsing npm/pnpm audit file: {self.audit_file.name}")
        
        with open(self.audit_file, 'r', encoding='utf-8') as f:
            audit_data = json.load(f)
        
        self.vulnerabilities = []
        
        # Check if audit_data is a list (pnpm sometimes returns a list)
        if isinstance(audit_data, list):
            print("   Warning: pnpm audit returned a list format, which is not fully supported")
            print("   Attempting to process as empty vulnerabilities")
            vulnerabilities = {}
        elif isinstance(audit_data, dict):
            # Check if this is pnpm audit format (has "actions" instead of "vulnerabilities")
            if 'actions' in audit_data and 'vulnerabilities' not in audit_data:
                # pnpm audit format: convert to npm format
                print("   Detected pnpm audit format, converting...")
                vulnerabilities = self._convert_pnpm_audit_to_npm_format(audit_data)
            else:
                # npm audit format
                vulnerabilities = audit_data.get('vulnerabilities', {})
        else:
            print(f"   Warning: Unexpected audit data type: {type(audit_data)}")
            vulnerabilities = {}
        
        total_vulns = len(vulnerabilities)
        print(f"   Found {total_vulns} vulnerable packages")
        
        processed_count = 0
        for pkg_name, vuln_info in vulnerabilities.items():
            processed_count += 1
            via_list = vuln_info.get('via', [])
            if not via_list:
                continue
            
            for via_item in via_list:
                if isinstance(via_item, str):
                    continue
                
                vuln_id = via_item.get('name', '')
                title = via_item.get('title', '')
                url = via_item.get('url', '')
                severity = via_item.get('severity', 'unknown')
                
                # Extract advisory ID for logging
                advisory_id = self._extract_advisory_id(url, vuln_id)
                
                # For pnpm numeric IDs, try to find GHSA ID and fetch details
                if not advisory_id and isinstance(vuln_id, (int, str)) and str(vuln_id).isdigit():
                    # Get actual vulnerable package from via_item if available
                    actual_package = via_item.get('actual_package', pkg_name)
                    # Try to find GHSA ID by querying OSV.dev with actual vulnerable package name
                    advisory_id = self._find_ghsa_by_package_and_id(actual_package, int(vuln_id))
                
                # Fetch detailed vulnerability information from OSV.dev API
                vuln_details = None
                if advisory_id:
                    print(f"   [{processed_count}/{total_vulns}] {pkg_name} ({advisory_id}): Fetching vulnerability details...")
                    vuln_details = self._fetch_vulnerability_details(advisory_id)
                    if vuln_details:
                        # Update title, severity, etc. from API
                        if vuln_details.get('summary'):
                            title = vuln_details['summary']
                        if vuln_details.get('severity'):
                            severity = vuln_details['severity']
                        if not url and vuln_details.get('id'):
                            url = f"https://github.com/advisories/{vuln_details['id']}" if vuln_details['id'].startswith('GHSA-') else f"https://osv.dev/vulnerability/{vuln_details['id']}"
                else:
                    print(f"   [{processed_count}/{total_vulns}] {pkg_name}: Extracting vulnerable functions...")
                
                vulnerable_functions = self._extract_vulnerable_functions(
                    pkg_name, advisory_id or vuln_id, url, title
                )
                
                if vulnerable_functions:
                    print(f"      → Extracted {len(vulnerable_functions)} functions: {', '.join(vulnerable_functions[:3])}{'...' if len(vulnerable_functions) > 3 else ''}")
                else:
                    print(f"      → No vulnerable functions extracted (may be package-level only)")
                
                # Build vulnerability data with detailed information
                vuln_data = {
                    'id': advisory_id or vuln_id or pkg_name,
                    'package': pkg_name,
                    'title': title,
                    'severity': severity,
                    'url': url,
                    'affected_range': vuln_info.get('range', ''),
                    'vulnerable_functions': vulnerable_functions,
                    'is_reachable': len(vulnerable_functions) > 0,
                    'cwe': via_item.get('cwe', []),
                    'cvss': via_item.get('cvss', {}),
                }
                
                # Add detailed information from OSV.dev API
                if vuln_details:
                    # CVE is extracted from aliases in _fetch_vulnerability_details
                    if vuln_details.get('cve'):
                        vuln_data['cve'] = vuln_details['cve']
                    # Fallback: check database_specific (some databases might have it there)
                    elif vuln_details.get('database_specific', {}).get('CVE'):
                        vuln_data['cve'] = vuln_details['database_specific']['CVE']
                    
                    # Severity from database_specific
                    if vuln_details.get('severity'):
                        vuln_data['severity'] = vuln_details['severity']
                    elif vuln_details.get('database_specific', {}).get('severity'):
                        vuln_data['severity'] = vuln_details['database_specific']['severity']
                    
                    # CVSS score (from NVD API via _fetch_cvss_from_nvd)
                    if vuln_details.get('cvss_score') is not None:
                        vuln_data['cvss'] = {'score': vuln_details['cvss_score']}
                    # Fallback: check database_specific
                    elif vuln_details.get('database_specific', {}).get('cvss_score'):
                        vuln_data['cvss'] = {'score': vuln_details['database_specific']['cvss_score']}
                    
                    if vuln_details.get('details'):
                        vuln_data['description'] = vuln_details['details']
                    if vuln_details.get('references'):
                        vuln_data['references'] = vuln_details['references']
                
                if not any(v['id'] == vuln_data['id'] and v['package'] == vuln_data['package'] 
                          for v in self.vulnerabilities):
                    self.vulnerabilities.append(vuln_data)
        
        vulns_with_funcs = [v for v in self.vulnerabilities if v.get('vulnerable_functions')]
        print(f"[SCA:VULN] Parsed {len(self.vulnerabilities)} vulnerabilities")
        print(f"   - With function information: {len(vulns_with_funcs)}")
        print(f"   - Without function information: {len(self.vulnerabilities) - len(vulns_with_funcs)}")
        print(f"   - Total vulnerable functions: {sum(len(v.get('vulnerable_functions', [])) for v in self.vulnerabilities)}")
        
        return self.vulnerabilities
    
    def _extract_vulnerable_functions(
        self, 
        pkg_name: str, 
        vuln_id: str, 
        url: str, 
        title: str
    ) -> List[str]:
        """Extract vulnerable function names from GitHub Advisory API or CVE"""
        functions = []
        
        # Try to extract from advisory API (supports both GHSA and CVE)
        # Also handle pnpm numeric IDs
        if ('github.com/advisories' in url or 
            vuln_id.startswith('GHSA-') or 
            vuln_id.startswith('CVE-') or
            (isinstance(vuln_id, (int, str)) and vuln_id.isdigit())):
            
            advisory_id = self._extract_advisory_id(url, vuln_id)
            
            # For pnpm numeric IDs, try to query OSV.dev by package name
            if not advisory_id and isinstance(vuln_id, (int, str)) and str(vuln_id).isdigit():
                # Try to find GHSA ID by querying OSV.dev with package name
                advisory_id = self._find_ghsa_by_package_and_id(pkg_name, vuln_id)
            
            if advisory_id:
                print(f"         [SCA:VULN:API] Fetching advisory data: {advisory_id}")
                api_functions = self._fetch_from_advisory_api(advisory_id)
                if api_functions:
                    functions.extend(api_functions)
                    print(f"         [SCA:VULN:API] Found {len(api_functions)} functions from advisory")
                else:
                    print(f"         [SCA:VULN:API] No functions found in advisory (no commit diffs available)")
        
        # Remove duplicates and return
        return list(set(functions)) if functions else []
    
    def _find_ghsa_by_package_and_id(self, package_name: str, numeric_id: int) -> Optional[str]:
        """
        Try to find GHSA ID by querying OSV.dev with package name
        pnpm numeric IDs are GitHub Advisory database IDs, but we need GHSA format
        
        Since we can't directly map numeric IDs to GHSA IDs, we query OSV.dev by package name
        and return the first GHSA ID found. This is not perfect but better than nothing.
        """
        try:
            import urllib.request
            import json
            import ssl
            
            # Query OSV.dev by package name
            query_url = "https://api.osv.dev/v1/query"
            query_data = {
                "package": {
                    "name": package_name,
                    "ecosystem": "npm"
                }
            }
            
            req = urllib.request.Request(query_url, data=json.dumps(query_data).encode('utf-8'))
            req.add_header('Content-Type', 'application/json')
            
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, context=ssl_context, timeout=10) as response:
                result = json.loads(response.read().decode('utf-8'))
                vulns = result.get('vulns', [])
                
                # Look for GHSA IDs in the results
                # Prefer recent vulnerabilities (they're usually sorted by date)
                ghsa_ids = []
                for vuln in vulns:
                    vuln_id = vuln.get('id', '')
                    if vuln_id.startswith('GHSA-'):
                        ghsa_ids.append(vuln_id)
                
                # Return the first GHSA ID found
                # Note: This is not perfect - we can't directly map numeric IDs to GHSA IDs
                # But it's better than leaving it as a numeric ID
                if ghsa_ids:
                    return ghsa_ids[0]
        except Exception:
            pass
        
        return None
    
    def _fetch_vulnerability_details(self, advisory_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch detailed vulnerability information from OSV.dev API
        
        Returns:
            Dictionary with vulnerability details including:
            - id: GHSA or CVE ID
            - summary: Title/description
            - severity: Severity level
            - database_specific: CVE, CVSS score, etc.
            - details: Detailed description
            - references: Reference URLs
        """
        try:
            import urllib.request
            import json
            import ssl
            
            osv_url = f"https://api.osv.dev/v1/vulns/{advisory_id}"
            req = urllib.request.Request(osv_url)
            req.add_header('Content-Type', 'application/json')
            req.add_header('User-Agent', 'npm-vulnerability-analyzer')
            
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, context=ssl_context, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                # Extract relevant information
                details = {
                    'id': data.get('id', advisory_id),
                    'summary': data.get('summary', ''),
                    'details': data.get('details', ''),
                    'severity': None,
                    'database_specific': data.get('database_specific', {}),
                    'references': data.get('references', []),
                    'aliases': data.get('aliases', [])
                }
                
                # Extract severity from database_specific or severity field
                db_specific = data.get('database_specific', {})
                if 'severity' in db_specific:
                    details['severity'] = db_specific['severity']
                elif 'severity' in data:
                    details['severity'] = data['severity']
                
                # Extract CVE from aliases (CVE is typically in aliases array, not database_specific)
                aliases = data.get('aliases', [])
                cve_aliases = [a for a in aliases if isinstance(a, str) and a.startswith('CVE-')]
                if cve_aliases:
                    # Use the first CVE found
                    details['cve'] = cve_aliases[0]
                # Fallback: check database_specific for CVE (some databases might have it there)
                elif 'CVE' in db_specific:
                    details['cve'] = db_specific['CVE']
                elif 'cve' in db_specific:
                    details['cve'] = db_specific['cve']
                
                # Extract CVSS score from OSV.dev if available (rare)
                if 'cvss_score' in db_specific:
                    details['cvss_score'] = db_specific['cvss_score']
                elif 'cvss' in db_specific:
                    details['cvss_score'] = db_specific['cvss']
                # Check for CVSS in severity field (some formats)
                elif 'severity' in db_specific and isinstance(db_specific['severity'], dict):
                    if 'score' in db_specific['severity']:
                        details['cvss_score'] = db_specific['severity']['score']
                
                # Check severity array for CVSS vector/score
                # OSV.dev sometimes provides severity as array with CVSS vectors
                severity_array = data.get('severity', [])
                if severity_array and not details.get('cvss_score'):
                    for severity_item in severity_array:
                        if isinstance(severity_item, dict):
                            # Check for direct score
                            if 'score' in severity_item:
                                try:
                                    score_val = severity_item['score']
                                    if isinstance(score_val, (int, float)):
                                        details['cvss_score'] = float(score_val)
                                        break
                                    elif isinstance(score_val, str) and score_val.replace('.', '').isdigit():
                                        details['cvss_score'] = float(score_val)
                                        break
                                except (ValueError, TypeError):
                                    pass
                            
                            # Check for CVSS vector string in 'score' field
                            score_field = severity_item.get('score', '')
                            if isinstance(score_field, str) and score_field.startswith('CVSS:'):
                                cvss_score = self._fetch_cvss_from_vector_api(score_field)
                                if cvss_score is not None:
                                    details['cvss_score'] = cvss_score
                                    break
                            
                            # Check for CVSS vector string in 'type' field
                            type_field = severity_item.get('type', '')
                            if isinstance(type_field, str) and type_field.startswith('CVSS:'):
                                cvss_score = self._fetch_cvss_from_vector_api(type_field)
                                if cvss_score is not None:
                                    details['cvss_score'] = cvss_score
                                    break
                
                # If we have a CVE, try to fetch CVSS score from NVD API
                if details.get('cve') and not details.get('cvss_score'):
                    cvss_score = self._fetch_cvss_from_nvd(details['cve'])
                    if cvss_score is not None:
                        details['cvss_score'] = cvss_score
                
                # If still no CVSS, try to get from OSV.dev query API (sometimes has more details)
                if not details.get('cvss_score') and advisory_id.startswith('GHSA-'):
                    # Try querying by the GHSA ID to see if we get more complete data
                    osv_cvss = self._fetch_cvss_from_osv_query(advisory_id)
                    if osv_cvss is not None:
                        details['cvss_score'] = osv_cvss
                
                # If still no CVSS score and we have a severity level, try to map it to a score
                # This is a fallback - better than null
                if not details.get('cvss_score') and details.get('severity'):
                    severity = details['severity'].upper()
                    # Rough mapping based on common CVSS ranges for each severity level
                    # These are conservative estimates that should cover most cases
                    severity_scores = {
                        'CRITICAL': 9.0,  # Critical vulnerabilities are typically 9.0-10.0
                        'HIGH': 7.5,      # High vulnerabilities are typically 7.0-8.9
                        'MODERATE': 5.0,  # Moderate vulnerabilities are typically 4.0-6.9
                        'MEDIUM': 5.0,    # Same as MODERATE
                        'LOW': 3.0        # Low vulnerabilities are typically 0.1-3.9
                    }
                    if severity in severity_scores:
                        # Use severity-based score as fallback when CVSS is not available
                        details['cvss_score'] = severity_scores[severity]
                
                return details
        except Exception as e:
            print(f"            [SCA:VULN:API] Error fetching details for {advisory_id}: {e}")
            return None
    
    def _fetch_cvss_from_nvd(self, cve_id: str) -> Optional[float]:
        """
        Fetch CVSS score from NVD (National Vulnerability Database) API
        
        Args:
            cve_id: CVE ID (e.g., CVE-2025-7783)
            
        Returns:
            CVSS score (float) or None if not found
        """
        try:
            import urllib.request
            import json
            import ssl
            
            # NVD API v2.0
            nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            req = urllib.request.Request(nvd_url)
            req.add_header('User-Agent', 'npm-vulnerability-analyzer')
            
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, context=ssl_context, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                vulnerabilities = data.get('vulnerabilities', [])
                if not vulnerabilities:
                    return None
                
                cve_item = vulnerabilities[0].get('cve', {})
                metrics = cve_item.get('metrics', {})
                
                # Try CVSS v4.0 first (newest)
                if 'cvssMetricV40' in metrics and metrics['cvssMetricV40']:
                    cvss_v40 = metrics['cvssMetricV40'][0]
                    cvss_data = cvss_v40.get('cvssData', {})
                    base_score = cvss_data.get('baseScore')
                    if base_score is not None:
                        return float(base_score)
                
                # Try CVSS v3.1
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    cvss_v31 = metrics['cvssMetricV31'][0]
                    cvss_data = cvss_v31.get('cvssData', {})
                    base_score = cvss_data.get('baseScore')
                    if base_score is not None:
                        return float(base_score)
                
                # Try CVSS v3.0
                if 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                    cvss_v30 = metrics['cvssMetricV30'][0]
                    cvss_data = cvss_v30.get('cvssData', {})
                    base_score = cvss_data.get('baseScore')
                    if base_score is not None:
                        return float(base_score)
                
                # Try CVSS v2 (fallback)
                if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                    cvss_v2 = metrics['cvssMetricV2'][0]
                    cvss_data = cvss_v2.get('cvssData', {})
                    base_score = cvss_data.get('baseScore')
                    if base_score is not None:
                        return float(base_score)
                
                return None
        except Exception as e:
            # Silently fail - CVSS is optional
            return None
    
    def _fetch_cvss_from_vector_api(self, vector_string: str) -> Optional[float]:
        """
        Fetch CVSS score from a CVSS vector string using online calculator API
        Falls back to simple calculation if API is unavailable
        
        Args:
            vector_string: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H")
            
        Returns:
            CVSS score (float) or None if not found
        """
        try:
            import urllib.request
            import json
            import ssl
            import re
            
            # Try to use a public CVSS calculator API
            # First, try parsing the vector to extract version and metrics
            if not vector_string or not vector_string.startswith('CVSS:'):
                return None
            
            # Extract version
            version_match = re.search(r'CVSS:(\d+\.\d+)', vector_string)
            if not version_match:
                return None
            
            version = version_match.group(1)
            
            # For CVSS 3.x, we can use a simple calculation
            # This is a simplified version but works for most cases
            if version.startswith('3'):
                # Parse metrics from vector
                metrics = {}
                parts = vector_string.split('/')
                for part in parts[1:]:
                    if ':' in part:
                        key, value = part.split(':', 1)
                        metrics[key] = value
                
                # Simplified CVSS 3.1 calculation
                # Impact metrics
                c = metrics.get('C', 'N')
                i = metrics.get('I', 'N')
                a = metrics.get('A', 'N')
                s = metrics.get('S', 'U')
                
                # Calculate Impact Sub Score (ISC)
                isc_base = 0.0
                if c == 'H':
                    isc_base += 0.56
                elif c == 'L':
                    isc_base += 0.22
                if i == 'H':
                    isc_base += 0.56
                elif i == 'L':
                    isc_base += 0.22
                if a == 'H':
                    isc_base += 0.56
                elif a == 'L':
                    isc_base += 0.22
                
                # Calculate Impact
                if s == 'C':
                    impact = 7.52 * (isc_base - 0.029) - 1.42 * pow(isc_base - 0.02, 15)
                else:
                    impact = 6.42 * isc_base
                
                impact = max(0, min(10, impact))
                
                # Exploitability metrics
                av = metrics.get('AV', 'N')
                ac = metrics.get('AC', 'L')
                pr = metrics.get('PR', 'N')
                ui = metrics.get('UI', 'N')
                
                # Exploitability scores
                av_scores = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
                ac_scores = {'L': 0.77, 'H': 0.44}
                pr_scores = {
                    'N': 0.85,
                    'L': 0.62 if s == 'U' else 0.68,
                    'H': 0.27 if s == 'U' else 0.5
                }
                ui_scores = {'N': 0.85, 'R': 0.62}
                
                exploitability = 8.22 * av_scores.get(av, 0.85) * ac_scores.get(ac, 0.77) * \
                                pr_scores.get(pr, 0.85) * ui_scores.get(ui, 0.85)
                
                # Base Score
                if impact <= 0:
                    base_score = 0.0
                elif s == 'U':
                    base_score = round((impact + exploitability) * 10) / 10
                else:
                    base_score = round((1.08 * (impact + exploitability)) * 10) / 10
                
                return min(10.0, max(0.0, base_score))
            
            return None
        except Exception:
            return None
    
    def _fetch_cvss_from_osv_query(self, advisory_id: str) -> Optional[float]:
        """
        Try to fetch CVSS score by querying OSV.dev with the advisory ID
        Sometimes the query API returns more complete data
        
        Args:
            advisory_id: GHSA or CVE ID
            
        Returns:
            CVSS score (float) or None if not found
        """
        try:
            import urllib.request
            import json
            import ssl
            
            # Query OSV.dev by ID
            query_url = "https://api.osv.dev/v1/vulns/" + advisory_id
            req = urllib.request.Request(query_url)
            req.add_header('Content-Type', 'application/json')
            req.add_header('User-Agent', 'npm-vulnerability-analyzer')
            
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, context=ssl_context, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                # Check severity array again (sometimes query returns different format)
                severity_array = data.get('severity', [])
                if severity_array:
                    for severity_item in severity_array:
                        if isinstance(severity_item, dict) and 'score' in severity_item:
                            try:
                                score_val = severity_item['score']
                                if isinstance(score_val, (int, float)):
                                    return float(score_val)
                                elif isinstance(score_val, str) and score_val.replace('.', '').isdigit():
                                    return float(score_val)
                            except (ValueError, TypeError):
                                continue
                
                return None
        except Exception:
            return None
    
    def _extract_advisory_id(self, url: str, vuln_id: str) -> Optional[str]:
        """
        Extract advisory ID (GHSA or CVE) from URL or vuln_id
        
        Supports:
        - GHSA: GHSA-xxxx-xxxx-xxxx (GitHub Security Advisory)
        - CVE: CVE-YYYY-NNNNNN (Common Vulnerabilities and Exposures)
        """
        # Check vuln_id first
        if vuln_id:
            if vuln_id.startswith('GHSA-'):
                return vuln_id
            elif vuln_id.startswith('CVE-'):
                return vuln_id
        
        # Try to extract from URL
        # GHSA pattern: GHSA-xxxx-xxxx-xxxx
        ghsa_match = re.search(r'GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}', url, re.IGNORECASE)
        if ghsa_match:
            return ghsa_match.group(0)
        
        # CVE pattern: CVE-YYYY-NNNNNN (4-7 digits)
        cve_match = re.search(r'CVE-\d{4}-\d{4,7}', url, re.IGNORECASE)
        if cve_match:
            return cve_match.group(0)
        
        return None
    
    def _fetch_from_advisory_api(self, advisory_id: str) -> List[str]:
        """
        Fetch vulnerable function information from OSV.dev API (no rate limit!)
        
        OSV.dev supports both GHSA and CVE IDs.
        Falls back to GitHub API only if OSV.dev fails.
        
        Args:
            advisory_id: GHSA ID (e.g., GHSA-xxxx-xxxx-xxxx) or CVE ID (e.g., CVE-YYYY-NNNNNN)
        """
        functions = []
        
        # Try OSV.dev API first (more lenient rate limits)
        # OSV.dev supports both GHSA and CVE formats
        try:
            osv_url = f"https://api.osv.dev/v1/vulns/{advisory_id}"
            print(f"            [SCA:VULN:API] Requesting: {osv_url}")
            req = urllib.request.Request(osv_url)
            req.add_header('Content-Type', 'application/json')
            req.add_header('User-Agent', 'npm-vulnerability-analyzer')
            
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, context=ssl_context, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                # Extract only from commit diff URLs (skip description parsing)
                # Only use diffing results for vulnerable function identification
                references = data.get('references', [])
                commit_urls = [ref.get('url', '') if isinstance(ref, dict) else str(ref) 
                              for ref in references if '/commit/' in (ref.get('url', '') if isinstance(ref, dict) else str(ref))]
                
                if commit_urls:
                    print(f"            [SCA:VULN:API] Found {len(commit_urls)} commit reference(s)")
                    
                    # Extract functions from each commit
                    all_commit_functions = []
                    for i, ref_url in enumerate(commit_urls, 1):
                        print(f"               [{i}/{len(commit_urls)}] Analyzing commit diff...")
                        commit_funcs = self._extract_from_commit_url(ref_url)
                        if commit_funcs:
                            all_commit_functions.append(set(commit_funcs))
                            print(f"                  → Extracted {len(commit_funcs)} functions from diff")
                        else:
                            print(f"                  → No functions extracted from diff")
                    
                    # Find intersection (common functions across all commits)
                    # This increases confidence that these are actually vulnerable functions
                    if all_commit_functions:
                        if len(all_commit_functions) == 1:
                            # Only one commit, use all functions
                            functions = list(all_commit_functions[0])
                        else:
                            # Multiple commits: find common functions
                            common_functions = set.intersection(*all_commit_functions)
                            if common_functions:
                                functions = list(common_functions)
                                print(f"            [SCA:VULN:API] Found {len(functions)} common function(s) across {len(all_commit_functions)} commits")
                            else:
                                # No common functions: use union (fallback)
                                # This handles cases where different commits fix different parts
                                all_functions = set.union(*all_commit_functions)
                                functions = list(all_functions)
                                print(f"            [SCA:VULN:API] No common functions found, using union: {len(functions)} function(s)")
                    else:
                        print(f"            [SCA:VULN:API] No functions extracted from any commit")
                else:
                    print(f"            [SCA:VULN:API] No commit references found in advisory")
                
                # Return intersection-based results (more accurate than union)
                return functions
        
        except (urllib.error.URLError, json.JSONDecodeError, KeyError) as e:
            # Fallback to GitHub API if OSV.dev fails (but this will likely hit rate limit)
            pass
        except Exception as e:
            print(f"            [SCA:VULN:API] Error: Failed to fetch advisory {advisory_id}: {e}")
        
        return functions
    
    def _extract_from_commit_url(self, commit_url: str) -> List[str]:
        """
        Extract vulnerable functions from commit diff using GitHub .patch URL
        
        Uses GitHub's .patch endpoint which doesn't count against API rate limits.
        This is the same URL format you see in browsers, so no authentication needed.
        
        Strategy:
        1. First, try to extract from diff context (faster, no additional requests)
        2. If function not found in diff context, fetch actual source file and search by line number
        """
        functions = []
        
        try:
            if 'github.com' not in commit_url or '/commit/' not in commit_url:
                return functions
            
            # Parse commit URL
            url_parts = commit_url.replace('https://github.com/', '').split('/commit/')
            if len(url_parts) != 2:
                return functions
            
            owner_repo = url_parts[0]
            sha = url_parts[1].split('#')[0].split('?')[0]  # Remove fragments/query params
            
            # Use .patch URL instead of API (no rate limit!)
            patch_url = f'https://github.com/{owner_repo}/commit/{sha}.patch'
            req = urllib.request.Request(patch_url)
            req.add_header('User-Agent', 'npm-vulnerability-analyzer')
            
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, context=ssl_context, timeout=10) as response:
                diff_text = response.read().decode('utf-8')
                lines = diff_text.split('\n')
                
                print(f"                  [SCA:VULN:DIFF] Parsing diff ({len(lines)} lines)...")
                
                current_file = None
                changed_lines = []
                file_changed_lines_map = {}  # Map file -> list of changed lines
                current_hunk_start = None  # Track current hunk's starting line number
                current_line_offset = 0  # Track line offset within hunk
                skip_file = False
                
                for i, line in enumerate(lines):
                    # Extract file path
                    if line.startswith('+++ b/'):
                        # Process previous file if exists
                        if current_file and not skip_file and current_file in file_changed_lines_map:
                            # Process the file's changed lines
                            file_changed_lines = file_changed_lines_map[current_file]
                            if file_changed_lines:
                                source_functions = self._extract_from_source_files(
                                    owner_repo, sha, file_changed_lines, current_file
                                )
                                if source_functions:
                                    functions.extend(source_functions)
                        
                        current_file = line.split('+++ b/')[-1]
                        current_hunk_start = None
                        current_line_offset = 0
                        
                        # Skip test files (file path pattern matching, no hardcoding)
                        if any(test_pattern in current_file.lower() for test_pattern in [
                            '.test.', '.spec.', '/test/', '/tests/', '/__tests__/',
                            '.test.js', '.test.ts', '.spec.js', '.spec.ts'
                        ]):
                            # Skip this file
                            skip_file = True
                            print(f"                     [SCA:VULN:DIFF] Skipping test file: {current_file}")
                            continue
                        else:
                            skip_file = False
                            # Initialize changed lines list for this file
                            if current_file not in file_changed_lines_map:
                                file_changed_lines_map[current_file] = []
                                print(f"                     [SCA:VULN:DIFF] Analyzing file: {current_file}")
                    
                    # Skip lines if we're in a test file
                    if skip_file:
                        continue
                    
                    # Extract class/function from header and track hunk start
                    # Example: @@ -155,7 +155,7 @@ export class ConfigCommentParser {
                    if line.startswith('@@'):
                        # Extract starting line number from diff header
                        hunk_match = re.search(r'@@\s*-(\d+),', line)
                        if hunk_match:
                            current_hunk_start = int(hunk_match.group(1))
                            current_line_offset = 0
                        
                        # Extract hunk start line number only (for calculating actual line numbers)
                        # No regex-based function/class extraction - all done via AST
                    
                    # Track line offset for calculating actual source line numbers
                    if line.startswith('-') and not line.startswith('---'):
                        # For removed lines, calculate actual line number
                        if current_hunk_start is not None and current_file and not skip_file:
                            actual_line = current_hunk_start + current_line_offset
                            line_data = (i, line[1:], False, actual_line, current_hunk_start)
                            changed_lines.append(line_data)
                            file_changed_lines_map[current_file].append(line_data)
                        current_line_offset += 1
                    elif line.startswith('+') and not line.startswith('+++'):
                        # For added lines, calculate actual line number (after the line offset)
                        if current_hunk_start is not None and current_file and not skip_file:
                            actual_line = current_hunk_start + current_line_offset
                            line_data = (i, line[1:], True, actual_line, current_hunk_start)
                            changed_lines.append(line_data)
                            file_changed_lines_map[current_file].append(line_data)
                        # Don't increment offset for added lines (they're new)
                    elif not line.startswith('@') and not line.startswith('diff') and not line.startswith('+++') and not line.startswith('---'):
                        # Context lines (unchanged) - increment offset
                        current_line_offset += 1
                    
                    # Skip regex-based method call extraction from changed lines
                    # Method calls will be extracted via AST from actual source files
                    # This is more accurate and handles complex cases better
                
                # Skip regex-based function extraction from diff context
                # All function extraction will be done via AST from actual source files
                # This ensures higher accuracy and better handling of edge cases
                # Changed line numbers are tracked in file_changed_lines_map
                # and will be processed by _extract_from_source_files which uses AST
                
                # Process the last file if exists
                if current_file and not skip_file and current_file in file_changed_lines_map:
                    file_changed_lines = file_changed_lines_map[current_file]
                    if file_changed_lines:
                        print(f"                     [SCA:VULN:DIFF] Processing {len(file_changed_lines)} changed lines in {current_file}")
                        source_functions = self._extract_from_source_files(
                            owner_repo, sha, file_changed_lines, current_file
                        )
                        if source_functions:
                            functions.extend(source_functions)
                            print(f"                        → Extracted {len(source_functions)} functions via AST")
                
                # Return raw diff parsing results without filtering
        
        except urllib.error.URLError as e:
            print(f"                  [SCA:VULN:DIFF] Error: Failed to fetch commit diff: {e}")
        except Exception as e:
            print(f"                  [SCA:VULN:DIFF] Error: Failed to parse commit diff: {e}")
        
        return functions
    
    def _extract_functions_with_ast(
        self, 
        source_code: str, 
        line_number: int, 
        file_path: Optional[str] = None
    ) -> List[str]:
        """
        Extract function name that contains the given line number using AST parsing only.
        Returns empty list if AST parser is not available (no regex fallback).
        
        Args:
            source_code: Full source code of the file
            line_number: Line number (1-indexed) where change occurred
            file_path: File path to determine parser type (optional)
        
        Returns:
            List of function names that contain this line
        """
        parser, lang = self._get_parser_for_file(file_path or '')
        
        if not parser or not TREE_SITTER_AVAILABLE:
            # AST parser not available - return empty list instead of regex fallback
            # This ensures we only use AST-based extraction for accuracy
            return []
        
        try:
            # Parse source code with appropriate parser
            tree = parser.parse(bytes(source_code, 'utf-8'))
            root_node = tree.root_node
            
            functions = []
            
            # Find function/method that contains the target line
            # line_number is 1-indexed, tree-sitter uses 0-indexed
            target_line_0_indexed = line_number - 1
            
            # Build parent map for easier parent lookup
            parent_map = {}
            def build_parent_map(node, parent=None):
                """Build a map of node -> parent for easier traversal"""
                if parent:
                    parent_map[node] = parent
                for child in node.children:
                    build_parent_map(child, node)
            
            build_parent_map(root_node)
            
            def get_function_name_from_node(node):
                """Extract function name from various node types"""
                node_type = node.type
                
                # Function declaration: function name() { ... }
                if node_type == 'function_declaration':
                    name_node = node.child_by_field_name('name')
                    if name_node:
                        return name_node.text.decode('utf-8')
                
                # Method definition: name() { ... } (class method or object method)
                elif node_type == 'method_definition':
                    name_node = node.child_by_field_name('name')
                    if name_node:
                        return name_node.text.decode('utf-8')
                
                # Arrow function or function expression: need to check parent
                elif node_type in ('arrow_function', 'function_expression'):
                    parent = parent_map.get(node)
                    if parent:
                        # Check if parent is variable_declarator (const name = function() { ... })
                        if parent.type == 'variable_declarator':
                            name_node = parent.child_by_field_name('name')
                            if name_node:
                                return name_node.text.decode('utf-8')
                        # Check if parent is assignment_expression (obj.method = function() { ... })
                        elif parent.type == 'assignment_expression':
                            left = parent.child_by_field_name('left')
                            if left:
                                left_text = source_code[left.start_byte:left.end_byte]
                                # Extract method name from assignment
                                # Handle any dot-separated path (e.g., "A.B.C.method" -> "method")
                                if '.' in left_text:
                                    parts = left_text.split('.')
                                    if parts:
                                        method_name = parts[-1].strip()
                                        # Remove trailing '=' if present
                                        if method_name.endswith('='):
                                            method_name = method_name[:-1].strip()
                                        return method_name
                                else:
                                    # No dot separator, extract directly
                                    method_name = left_text.strip()
                                    if method_name.endswith('='):
                                        method_name = method_name[:-1].strip()
                                    return method_name
                        # Check if parent is property (object method: { name: function() { ... } })
                        elif parent.type == 'property':
                            key_node = parent.child_by_field_name('key')
                            if key_node:
                                return key_node.text.decode('utf-8')
                        # Check if parent is pair (object literal: { name: function() { ... } })
                        elif parent.type == 'pair':
                            key_node = parent.child_by_field_name('key')
                            if key_node:
                                # key could be property_identifier or string
                                key_text = key_node.text.decode('utf-8')
                                # Remove quotes if it's a string
                                if key_text.startswith('"') or key_text.startswith("'"):
                                    key_text = key_text[1:-1]
                                return key_text
                
                # Property with function: { name: function() { ... } } or { name: () => { ... } }
                elif node_type == 'property':
                    value_node = node.child_by_field_name('value')
                    key_node = node.child_by_field_name('key')
                    if value_node and key_node:
                        # Check if value is a function (function_expression, arrow_function, or method_definition)
                        if value_node.type in ('function_expression', 'arrow_function', 'generator_function'):
                            return key_node.text.decode('utf-8')
                
                return None
            
            def traverse_node(node):
                """Recursively traverse AST to find function containing the line"""
                # Check if this node contains the target line
                node_start_line = node.start_point[0]  # 0-indexed
                node_end_line = node.end_point[0]  # 0-indexed
                
                if node_start_line <= target_line_0_indexed <= node_end_line:
                    # Try to extract function name from this node
                    func_name = get_function_name_from_node(node)
                    if func_name and func_name not in functions:
                        functions.append(func_name)
                    
                    # Also check if this is a property and the value contains the line
                    # (for cases like { name: function() { ... } } where the function is nested)
                    if node.type == 'property':
                        value_node = node.child_by_field_name('value')
                        if value_node:
                            value_start = value_node.start_point[0]
                            value_end = value_node.end_point[0]
                            if value_start <= target_line_0_indexed <= value_end:
                                # The changed line is inside the property's value
                                if value_node.type in ('function_expression', 'arrow_function', 'generator_function'):
                                    key_node = node.child_by_field_name('key')
                                    if key_node:
                                        prop_func_name = key_node.text.decode('utf-8')
                                        if prop_func_name and prop_func_name not in functions:
                                            functions.append(prop_func_name)
                    
                    # Continue traversing children (more specific matches might be deeper)
                    for child in node.children:
                        traverse_node(child)
                else:
                    # This node doesn't contain the target line, skip its children
                    pass
            
                                    # Start traversal from root
            traverse_node(root_node)
            
            # Return functions found via AST (even if empty)
            # No regex fallback - we only use AST for accuracy
            return functions
        
        except Exception as e:
            # On error, return empty list instead of regex fallback
            # AST-based extraction only
            return []

    def _extract_from_source_files(
        self, 
        owner_repo: str, 
        sha: str, 
        changed_lines: List[tuple], 
        current_file: Optional[str]
    ) -> List[str]:
        """
        Extract functions by fetching actual source files and searching by line number
        
        This is a fallback when diff context doesn't contain the function definitions.
        """
        functions = []
        
        if not current_file:
            return functions
        
        # Skip test files
        if any(test_pattern in current_file.lower() for test_pattern in [
            '.test.', '.spec.', '/test/', '/tests/', '/__tests__/',
            '.test.js', '.test.ts', '.spec.js', '.spec.ts'
        ]):
            return functions
        
        try:
            # Fetch actual source file from GitHub
            raw_url = f'https://raw.githubusercontent.com/{owner_repo}/{sha}/{current_file}'
            print(f"                        [SCA:VULN:AST] Fetching source file: {current_file}")
            req = urllib.request.Request(raw_url)
            req.add_header('User-Agent', 'npm-vulnerability-analyzer')
            
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, context=ssl_context, timeout=10) as response:
                source_code = response.read().decode('utf-8')
                source_lines = source_code.split('\n')
                
                parser, lang = self._get_parser_for_file(current_file)
                if parser:
                    print(f"                           [SCA:VULN:AST] Using {lang} AST parser")
                else:
                    print(f"                           [SCA:VULN:AST] Warning: No AST parser available for {current_file}")
                
                # Group changed lines by whether they were added or removed
                removed_lines = []  # 취약한 코드 (삭제된 라인)
                added_lines = []    # 패치 코드 (추가된 라인)
                
                for line_data in changed_lines:
                    if len(line_data) >= 4:
                        _, _, is_added, actual_line = line_data[:4]
                        
                        if actual_line and actual_line > 0 and actual_line <= len(source_lines):
                            if not is_added:
                                # 삭제된 라인: 취약한 코드가 있던 부분
                                removed_lines.append(actual_line)
                            else:
                                # 추가된 라인: 패치 코드 (추출하지 않음)
                                added_lines.append(actual_line)
                
                # 취약한 함수 추출: 삭제된 라인에 해당하는 함수만 추출
                # (추가만 되고 삭제가 없는 함수는 취약한 함수가 아님)
                # 실제 취약한 함수만 추출 (클래스 이름은 추출하지 않음)
                for removed_line in removed_lines:
                    extracted_funcs = self._extract_functions_with_ast(
                        source_code, removed_line, current_file
                    )
                    if extracted_funcs:
                        functions.extend(extracted_funcs)
                
        except urllib.error.URLError:
            # Silently fail - source file might not be accessible
            pass
        except Exception:
            # Silently fail for any other errors
            pass
        
        return functions

    def _load_project_packages(self) -> set:
        """Load all packages from package.json"""
        packages = set()
        
        if not self.project_path:
            return packages
        
        package_json = self.project_path / 'package.json'
        if not package_json.exists():
            return packages
        
        try:
            with open(package_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            deps = data.get('dependencies', {})
            packages.update(deps.keys())
            
            dev_deps = data.get('devDependencies', {})
            packages.update(dev_deps.keys())
            
            peer_deps = data.get('peerDependencies', {})
            packages.update(peer_deps.keys())
        
        except Exception:
            pass
        
        return packages
