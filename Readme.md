<p align="center">
<img src="./banner.svg" alt="Patchlens Banner" width="100%">
</p>

## Hii everyone My name is MJM AKA Mohammad Juned Malik , it's going to be my second project which i am going to avail this publically and don't mind my english or it's grammar if anything goes wrong while writing and I have written this code as most simplest form as possible so anyone who knows some basic python, OOPs(Class) and it's methods and python libraries can easily understand this project also mostly i have imported files from one other so don't get confused and i have written some comments also in some files , so let's start our project description :- 

# PatchLens - Web Security Assessment & Fix Verification Engine 

It's an Web security scanner that's can that find easily but the different is that normail scanner only scans and list warning one time and forgets but the Patchlens web security scanner that not only audit websites butttt... it also save previous scans by sqlite database to check whether the any problem or vulnerability is fixed or it's reappearing/ reopening over time. and now below here is how it get it done :-

1. BodyGuard and Crawler (AKA scope.py & crawler.py) : it validates/checks the given or targeted url and runs a bounded breadth first search (BFS) , crawler strictly stays on the main domain not looking into external links. 
2. Security Auditer/Checker (AKA patchlens/checks) : it checks every header, weak cookie, insecure mix content and tls/ssh certifications. 
3. Fix verification Engine (AKA historydb.py) :   it stores findings in sqlite database using SHA-256 fingerprint, it even rescans the target and compares them with previous scan automatically and generates or tell us whether a issue is new, open , resolved or reopened.
4. Reporter and CLI (AKA reporter.py & main.py) : it presents the summary in the terminall cleanly with an banner (if you are curious about banner you can look up  and see the very big Patchlens written that's the banner ) , it counts severity level and generates an report in json . 

## What i have build till now:-

-**Strict scope boundaries** : it rejects rejects external domain, sub-domain and protocols like:- mailto:, tel: and javascript: .
-**Web crawler** : it configures page count and crawling depth of it with url normalization.
-**Http security audit/check** : it checks misconfigured or missing x-frame options , hsts(strict transfer policy), csp (content security policy) x-content type options , referrer policy and the leaked server banner tokens .
-**Cookie security analyzer** : it checks/audit cookie header for missing secure, httponly and samesite .
-**Mixed content detector** : it raises insecure http scripts, stylesheets and iframe options from inside https pages.
-**TLS/SSH Verification** : it checks https availability, validation, expiration and also redirecting http to https.
-**Stable Fingerprinting** : it involves 16 characters SHA-256 hashes so findings can be tracked.
-**Fix verfication lifecycle** : it classifies findgings automatically in scans .
-**Autometed tests** : created tests for scope, checkers, and history.


## Files :- 
-'main.py' : CLI and report export.
-'patchlens/scope.py' : it validated approved origins and ensures crawler focus on target domain.
-'patchlens/http_client' : safe rate-limited of http and wrapped with timeout & redirect protection http to https.
-'patchlens/crawler.py' : it bounded by bfs  with depth and page limits.
-'patchlens/findings.py' : it normalized finding dataclasses with severity, confidence, stable SHA-256 fingerprinting and status tracking .
-'patchlens/historydb.py' : it's sqlite database and fix verification engine. 
-'patchlens/reporter.py' : it summarize the findings by severity then prints output in the terminal and save it in json file.
-'patchlens/checks/headers.py' : it checks module of 6 for http header.
-'patchlens/checks/cookies.py' : check header of cookie for secure , httponly and samesite. 
-'patchlens/checks/mixed.py' : it checks module detecting http resources loaded on web pages. 
-'patchlens/checks/tls.py' : it checks for tls/ssl certificate and redirection .
-'tests/test_scope.py' : automated unit tests for url normalization and domain rules .
-'tests/test_checks.py' : automated unit tests for headers, cookies and mixed .
-'tests/test_his.py' : automated unit tests for sqlite and fix verification .
-'requirement.txt' : list of python dependencies Beautifulsoup, requests, pytest .


## What you need 
-Linux/ macOS / Windows
-Python 3.10 or higher

## How to run it ! (write the commands in the terminal or just copy and paste)
### 1. set up ur virtual environment :
# it creates virtual environment
python3 -m venv venv

# activate virtual environment 
source venv/bin/activate

# install dependencies 
pip install -r requirement.txt 

### 2. Run a basic scan against a target url :
python main.py --target https://example.com

### 3. Run a proper scan and save in json :
python main.py  --target https:example.com --max_pages 5 --max-depth 2 --json report.json

### 4. Run fix verification engine :
run the same scan on the same target and see the results 

### 5. to run the automated unit tests: 
python -m pytest tests/ -v 




## it's safe to use in the terminal , it's not going to hack your system anything it's safe and if any bug or error arises and if there is any updation can be done , let me know ! 
