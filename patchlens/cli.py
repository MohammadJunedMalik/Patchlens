import argparse 
from patchlens.engine import Scanengine
from patchlens.reporter import Reporter

Banner = r"""
    ██████╗  █████╗ ████████╗ ██████╗██╗  ██╗██╗     ███████╗███╗   ██╗███████╗ 
    ██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██║  ██║██║     ██╔════╝████╗  ██║██╔════╝ 
    ██████╔╝███████║   ██║   ██║     ███████║██║     █████╗  ██╔██╗ ██║███████╗ 
    ██╔═══╝ ██╔══██║   ██║   ██║     ██╔══██║██║     ██╔══╝  ██║╚██╗██║╚════██║ 
    ██║     ██║  ██║   ██║   ╚██████╗██║  ██║███████╗███████╗██║ ╚████║███████║
    ╚═╝     ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝
                     [+] Find. Explain. Fix. Verify. [+]
    """

def main():
    print(Banner)
    pars = argparse.ArgumentParser(description="Patchlens - Web Security Assessment & Fix Verification Engine")
    pars.add_argument("--target", required=True, help="Target URL to scan")
    pars.add_argument("--max-pages", type=int, default=10, help="Maximum number of pages to crawl (default: 10)")
    pars.add_argument("--max-depth", type=int, default=2, help="Maximum crawl depth (default: 2)")
    pars.add_argument("--json", type=str, default="", help="Path to export report in JSON format")
    args = pars.parse_args()

    inst = Scanengine(args.max_pages, args.max_depth)
    findings = inst.scan(args.target)

    repo = Reporter(findings, target_url=args.target)
    repo.summary()
    if args.json:
        repo.in_json(args.json)

if __name__ == "__main__":
    main()
