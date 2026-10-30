from patchlens.scope import Scope
from patchlens.http_client import SafeHttp
from patchlens.crawler import Crawler
from patchlens.checks.headers import Headerchecker
from patchlens.checks.cookies import Cookiechecker
from patchlens.checks.mixed import Mixedcontentchecker
from patchlens.checks.tls import Tlschecker 
from patchlens.engine import Scanengine
from patchlens.reporter import Reporter
from patchlens.historydb import Historydatabase

scope = Scope("https://httpbin.org")
client = SafeHttp(scope)

print("<---- Test1:- Out of Scope ----->")
test1 = client.get("http://google.com")
print(test1)
print(client.skipped)

print("/n<---- Test2:- In scope page------>")
test2 = client.get("https://httpbin.org/get")
print(test2)
print(client.skipped[-1])

print("\n<----- Test3:- Handling of Dangerous-------> ")
test3 = client.get("https://httpbin.org/redirect-to?url=https://evil.com")
print(test3)
print(client.skipped[-1])

print("\n<------- test4:- ")
crawler = Crawler(client,max_pages=3, max_depth = 1)
pages = crawler.crawl("https://httpbin.org/html")
print(len(pages))
print(crawler.visited)

print("\n<---------test5:- Real header security analysis------------>")
header_checker = Headerchecker()
findings = header_checker.check_all("https://httpbin.org/get", test2.headers)
print(f"total findings discovered: {len(findings)}")
for f in findings:
    print(f"{f.check_id}\n{f.title}\n{f.severity}")


print("\n<---------test 5:- Cookiechecker---------->")
c = Cookiechecker()
result = c.check_all("https://example.com",{"Set-Cookie": "session_id=abc123 ; paths=/"})
for i in result:
    print(f"[{i.check_id}] {i.title} ({i.severity})")

print("\n<---------- Test 6 : Mixed Content checker ------->")
mixed_checker = Mixedcontentchecker()

with open("index.html", 'r') as f:
    sample_html = f.read()

result = mixed_checker.check_all("https://example.com", sample_html)
print(f"Total mixed content findings: {len(result)}")

for i in result:
    print(f"\n[{i.check_id}], {i.title}, ({i.severity.name if hasattr(i.severity, 'name') else i.severity}) ")
    print(f" Target_key: {i.target_key}")
    print(f" Evidence: {i.evidence}")
    print(f" Actual: {i.actual}")


print("\n<------------ test 7 : tls checker---------->")

tls = Tlschecker()

result_tls = tls.check_all("https://httpbin.org")

print(f"Total findings for httpbin.org (should be 0) : {len(result_tls)}")

for r in result_tls:
    print(f"[{r.check_id}]  {r.title} ({r.severity.name}) ")

print("\n<--- tls expire check---->")
result_tls_expire = tls.check_all("https://expired.badssl.com")
print(f" total expired tls : {len(result_tls_expire)}")
for fr in result_tls_expire:
    print(f"[{fr.check_id}]  {fr.title} ({fr.severity.name}) -> {fr.evidence}")

print("\n<----------------test8:- Full scan engine ------------>")
engine = Scanengine(max_pages = 3, max_depth = 1)
result_scan = engine.scan("https://httpbin.org")
print(f"total unique findings are: {len(result_scan)}")
for rs in result_scan:
    print(f"[{rs.severity}] {rs.check_id}: {rs.title} :- {rs.url}")


print("\n<----------------test9 :- report test ------------------>")
reporter = Reporter(result,target_url = "https://httpbin.org")

reporter.summary()

reporter.in_json("scan_report.json")
print("\n saved the report in json")

print("\n<--------------- test 10 :- history database test -------------->")
test = Historydatabase("test2.db")
finding1 = test.scan_verification("https://httpbin.org", result_scan)
for tf in finding1:
    print(f"status : {tf.status}")

save = test.scan_save("scan_1", "https://httpbin.org", finding1)
finding2 = test.scan_verification("https://httpbin.org", result_scan[:5])
for stf in finding2:
    print(f"status : {stf.status}")

    


