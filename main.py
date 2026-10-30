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

print(Banner)
pars = argparse.ArgumentParser(description = "Patchlens CLI")
pars.add_argument("--target",  required = True, help="Target URL")
pars.add_argument("--max-pages", type = int, default = 10)
pars.add_argument("--max-depth", type = int, default = 2)
pars.add_argument("--json", type = str, default = "")
args = pars.parse_args()
inst = Scanengine(args.max_pages, args.max_depth)
findings = inst.scan(args.target)

repo = Reporter(findings, target_url = args.target)
repo_smry = repo.summary()
if args.json:
    repo.in_json(args.json) 


