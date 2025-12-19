#!/usr/bin/env python3
import argparse
import sys
import json
from datetime import datetime
from pathlib import Path
from rich import print
from scanner.runner.manager import MCPScannerManager
from scanner.ui.colors import make_console, build_gradient_text
from scanner.analyzers.common.utils import is_github_repo, filter_findings_by_severity
from scanner.analyzers.common.constants import SEVERITY_INFO, OUTPUT_DIR, ARTIFACTS_DIR

def print_banner():
    console = make_console()
    banner_text = (
        "\n"
        "   ██████╗  ██████╗ ███╗   ███╗████████╗ ██████╗  ██████╗ ██╗\n"
        "   ██╔══██╗██╔═══██╗████╗ ████║╚══██╔══╝██╔═══██╗██╔═══██╗██║\n"
        "   ██████╔╝██║   ██║██╔████╔██║   ██║   ██║   ██║██║   ██║██║\n"
        "   ██╔══██╗██║   ██║██║╚██╔╝██║   ██║   ██║   ██║██║   ██║██║\n"
        "   ██████╔╝╚██████╔╝██║ ╚═╝ ██║   ██║   ╚██████╔╝╚██████╔╝███████╗\n"
        "   ╚═════╝  ╚═════╝ ╚═╝     ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝\n"
        "   ███████╗ ██████╗ █████╗ ███╗   ██╗\n"
        "   ██╔════╝██╔════╝██╔══██╗████╗  ██║\n"
        "   ███████╗██║     ███████║██╔██╗ ██║\n"
        "   ╚════██║██║     ██╔══██║██║╚██╗██║\n"
        "   ███████║╚██████╗██║  ██║██║ ╚████║\n"
        "   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝\n"
    )
    text = build_gradient_text(banner_text, start_hex="#6c5d53", end_hex="#dfd3c3", bold=True)
    console.print(text)

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="MCP Server Scanner - Built by BOMTool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  bomtool-scan -p /path/to/local/repo\n  bomtool-scan --path https://github.com/user/repo -v -w 8\n",
    )

    parser.add_argument("-p", "--path", help="Local repository path or GitHub URL")
    parser.add_argument("-w", "--workers", type=int, default=4, help="Number of parallel workers for scanning (default: 4)")
    args = parser.parse_args()

    try:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
        
        if args.workers < 1:
            print("[red][!][/red] --workers must be at least 1")
            sys.exit(1)
        
        manager = MCPScannerManager(temp_dir=str(ARTIFACTS_DIR), max_workers=args.workers)
        
        if not args.path:
            print("[red][!][/red] --path is required")
            sys.exit(1)
        
        is_github = is_github_repo(args.path)
        
        if is_github:
            print(f"[blue]GitHub repository detected:[/blue] {args.path}")
        else:
            workdir = Path(args.path).resolve()
            if not workdir.exists():
                print(f"[red][!][/red] Path not found: {workdir}")
                sys.exit(1)
        
        results = manager.scan_repository_full(args.path)
        
        from scanner.analyzers.common.utils import extract_repo_name
        output_name = extract_repo_name(args.path)
        safe_output_name = "".join(c if c.isalnum() or c in ('-', '_') else '_' for c in output_name)
        
        server_risk = results.get('scan_info', {}).get('server_risk_score', 0.0)
        if server_risk >= 9.0:
            risk_color = "red"
        elif server_risk >= 7.0:
            risk_color = "red"
        elif server_risk >= 5.0:
            risk_color = "yellow"
        else:
            risk_color = "green"
        
        print(f"\n[{risk_color}]Server Risk Score: {server_risk:.1f}/10.0[/{risk_color}]")
        
        out = OUTPUT_DIR / f"{safe_output_name}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[green]Detailed results saved:[/green] {out.resolve()}")

    except Exception as e:
        print(f"[red][!][/red] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()