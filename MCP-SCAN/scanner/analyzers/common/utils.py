import re
from pathlib import Path
from typing import List, Dict, Any, Tuple

from scanner.analyzers.common.constants import GITHUB_PREFIXES


def is_github_repo(path: str) -> bool:
    if any(path.startswith(prefix) for prefix in GITHUB_PREFIXES):
        return True
    
    github_url_pattern = r'https?://github\.com/[^/]+/[^/]+(/tree/|/blob/|/commit/)?'
    return bool(re.match(github_url_pattern, path))


def get_default_branch(github_url: str) -> str:
    import subprocess
    try:
        result = subprocess.run(
            ['git', 'ls-remote', '--symref', github_url, 'HEAD'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.startswith('ref:'):
                    parts = line.split('\t')[0].split('/')
                    if len(parts) >= 3:
                        return parts[-1]
    except Exception:
        pass
    return 'main'


def normalize_github_url(github_url: str) -> Tuple[str, str]:
    url = github_url.rstrip('/')
    
    tree_match = re.match(r'(https?://github\.com/[^/]+/[^/]+)/tree/([^/]+)', url)
    if tree_match:
        base_url = tree_match.group(1)
        branch_or_commit = tree_match.group(2)
        return base_url, branch_or_commit
    
    blob_match = re.match(r'(https?://github\.com/[^/]+/[^/]+)/blob/([^/]+)', url)
    if blob_match:
        base_url = blob_match.group(1)
        branch_or_commit = blob_match.group(2)
        return base_url, branch_or_commit
    
    commit_match = re.match(r'(https?://github\.com/[^/]+/[^/]+)/commit/([^/]+)', url)
    if commit_match:
        base_url = commit_match.group(1)
        commit_hash = commit_match.group(2)
        return base_url, commit_hash
    
    base_match = re.match(r'(https?://github\.com/[^/]+/[^/]+)', url)
    if base_match:
        base_url = base_match.group(1)
        default_branch = get_default_branch(base_url)
        return base_url, default_branch
    
    return url, 'main'


def extract_repo_name(repo_path: str) -> str:
    if is_github_repo(repo_path):
        base_url, _ = normalize_github_url(repo_path)
        repo_name = base_url.rstrip('/').split('/')[-1]
        return repo_name[:-4] if repo_name.endswith('.git') else repo_name
    else:
        return Path(repo_path).name


def filter_findings_by_severity(findings: List[Dict[str, Any]], 
                                exclude_severities: List[str] = None) -> List[Dict[str, Any]]:
    if exclude_severities is None:
        exclude_severities = ['info']
    
    exclude_lower = [s.lower() for s in exclude_severities]
    return [f for f in findings if f.get("severity", "").lower() not in exclude_lower]


def count_findings_by_category(findings: List[Dict[str, Any]], 
                               category: str) -> Dict[str, int]:
    counts = {}
    for finding in findings:
        value = finding.get(category, "unknown")
        counts[value] = counts.get(value, 0) + 1
    return counts


def calculate_server_risk_score(findings: List[Any]) -> float:
    if not findings:
        return 0.0
    
    all_risk_scores = []
    non_info_findings = []
    non_info_risk_scores = []
    
    for f in findings:
        severity = f.get('severity') if isinstance(f, dict) else f.severity
        
        if hasattr(f, 'severity_weight'):
            weight = f.severity_weight
        else:
            from scanner.analyzers.common.constants import SEVERITY_WEIGHTS
            weight = SEVERITY_WEIGHTS.get(severity, 1)
        
        confidence = f.get('confidence') if isinstance(f, dict) else getattr(f, 'confidence', 1.0)
        risk_score = weight * confidence
        
        all_risk_scores.append(risk_score)
        
        if severity != 'info':
            non_info_findings.append(f)
            non_info_risk_scores.append(risk_score)
    
    max_risk = max(all_risk_scores) if all_risk_scores else 0.0
    
    avg_risk = sum(non_info_risk_scores) / len(non_info_risk_scores) if non_info_risk_scores else 0.0
    
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for f in findings:
        severity = f.get('severity') if isinstance(f, dict) else f.severity
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    weighted_count = (
        severity_counts['critical'] * 10 +
        severity_counts['high'] * 7 +
        severity_counts['medium'] * 4 +
        severity_counts['low'] * 2
    )
    count_factor = min(10.0, weighted_count / 10.0)
    
    server_risk = max_risk * 0.4 + avg_risk * 0.3 + count_factor * 0.3
    
    return round(server_risk, 2)


def extract_var_name(arg: str, 
                     strip_quotes: bool = True,
                     strip_pointers: bool = True,
                     handle_type_cast: bool = True) -> str:
    if not arg:
        return ""
    
    original_arg = arg
    
    if strip_quotes:
        arg = arg.strip()
        if (arg.startswith('"') and arg.endswith('"')) or \
           (arg.startswith("'") and arg.endswith("'")) or \
           (arg.startswith('`') and arg.endswith('`')):
            return ""
        arg = arg.strip('"\'`')
    
    if arg.isdigit():
        return ""
    
    if arg in ('()', '[]', '{}'):
        return ""
    
    if handle_type_cast and '(' in arg and ')' in arg:
        parts = arg.split('(', 1)
        if len(parts) == 2:
            func_part = parts[0].strip()
            args_part = parts[1].rstrip(')').strip()
            
            type_casts = ['[]byte', 'string', 'int', 'int64', 'uint', 'uint64',
                         'float32', 'float64', 'bool', '[]string', '[]int', 
                         'int32', 'uint32', 'byte', 'rune']
            if func_part in type_casts:
                return args_part
            
            return ""
    
    if strip_pointers:
        arg = arg.strip('*&')
    
    return arg.strip()