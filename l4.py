#!/usr/bin/env python3
import subprocess
import argparse
import os
import random
import asyncio
import httpx

CONCURRENCY = 50

# Lista med olika User-Agent-strängar
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0",
    "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/    134.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36>",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:70.0) Gecko/20100101 Firefox/70.0",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:70.0) Gecko/20100101 Firefox/70.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 OPR/65.0.3467.48",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 OPR/65.0.3467.48",
    "Mozilla/5.0 (iPad; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30",
]


def run_cmd(command, cwd=None):
    print(f"[+] Running: {command}")
    subprocess.run(command, shell=True, cwd=cwd)


async def ffuf_like_discovery(target, wordlist_path, user_agents):

    print(f"[+] Startar endpoint discovery on {target} with rotating User-Agents")
    os.makedirs(os.path.join("l4-recon", target), exist_ok=True)
    with open(wordlist_path) as f:
        endpoints = [line.strip() for line in f if line.strip()]

    sem = asyncio.Semaphore(CONCURRENCY)

    async def fetch(endpoint):
        url = f"https://{target}/{endpoint.lstrip('/')}"
        headers = {"User-Agent": random.choice(user_agents)}
        async with sem:
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    r = await client.get(url, headers=headers, follow_redirects=True)
                    if r.status_code != 404:
                        print(f"[{r.status_code}] {url}")
                        output_path = os.path.join(
                            "l4-recon", target, f"{target}_fuzz_hits.txt"
                        )
                with open(output_path, "a") as f_out:
                    f_out.write(f"{r.status_code} {url}\n")
            except Exception:
                pass

    await asyncio.gather(*[fetch(e) for e in endpoints])


def recon(target, include_subdomains=False, scope_file=None, skip_passive=False):
    target_dir = f"l4-recon/{target}"
    os.makedirs(target_dir, exist_ok=True)

    # Använd slumpmässig User-Agent
    headers = f"-H 'User-Agent: {random.choice(USER_AGENTS)}'"

    if not skip_passive:
        # 1. Hämta URL:er
        run_cmd(f"gau {target} | tee urls_raw.txt", cwd=target_dir)
        run_cmd(f"waybackurls {target} >> urls_raw.txt", cwd=target_dir)
        #run_cmd(f"waybackrobots {target} >> urls_raw.txt", cwd=target_dir)
        run_cmd("sort -u urls_raw.txt > urls_all.txt", cwd=target_dir)

        # 2. Filtrera parametrar
        run_cmd(
            "grep '=' urls_all.txt | grep -vE '\\.(jpg|jpeg|png|gif|svg|css|js|woff|ico)$' | sort -u >      urls_with_params.txt",
        cwd=target_dir,
        )
    
    # Skicka endast urls med normaliserade parametrar. vill inte testa samma parameter med 1000 olika ID:n
        run_cmd("cat urls_with_params.txt | tr -cd '\\11\\12\\15\\40-\\176' | sed -E 's/([?&][^=&#]+)=?[^&#]*/\1=VAR/g' | sort -u > urls_normalized.txt", cwd=target_dir)

    else:
        print("[*] Skipping passive recon steps (--skip-passive)")
        
    # 3. Dalfox (XSS)
    run_cmd(
        "dalfox file urls_normalized.txt --only-poc -o xss_results.txt", cwd=target_dir
    )

    # 4. Nuclei
    run_cmd(
        "nuclei -l urls_normalized.txt -iserver https://server-two-rho.vercel.app/exfil-metadata -o nuclei_results.txt",
        cwd=target_dir,
    )

    # 5. Open Redirect
    #run_cmd(
     #   "cat urls_with_params.txt | qsreplace 'https://server-two-rho.vercel.app/redirected-here' | httpx #-follow-redirects -silent > redirect_check.txt",
     #   cwd=target_dir,
    #)

    # 6. HTTP Headers
    run_cmd(
        "cat urls_all.txt | httpx -silent -status-code -title -tech-detect -web-server -o headers_scan.txt",
        cwd=target_dir,
    )

    # 7. JavaScript scraping
    run_cmd("cat urls_all.txt | grep '\\.js' | sort -u > js_files.txt", cwd=target_dir)
    run_cmd(
        "cat js_files.txt | xargs -I@ curl -s @ | linkfinder -i stdin -o cli > endpoints_from_js.txt",
        cwd=target_dir,
    )

    # 8. Arjun (Blind parameters)
    # run_cmd("arjun -i urls_all.txt -oT arjun_params.txt -t 10")

    # 9. Secrets i URL
    run_cmd(
        "grep -Eoi '([a-z0-9_-]*key|token|secret)[=:][^&]+' urls_all.txt | tee secrets_in_urls.txt",
        cwd=target_dir,
    )

    # 10. JS pattern analysis
    run_cmd("cat js_files.txt | xargs -I@ curl -s @ > js_combined.js", cwd=target_dir)
    run_cmd(
        r"grep -Ei 'localStorage|document\.cookie|innerHTML|document\.write|dangerouslySetInnerHTML|fetch\(|XMLHttpRequest|feature[_-]?flags?|featureflag|experiment|admin|administrator' js_combined.js > js_issues.txt"
,
        cwd=target_dir,
    )

    # 11. Subdomain enumeration (om flagga är satt)
    if include_subdomains:
        run_cmd(f"subfinder -d {target} -o subdomains.txt", cwd=target_dir)
        run_cmd(
            "cat subdomains.txt | httpx -silent > live_subdomains.txt", cwd=target_dir
        )

    # 12. Scope scanning (om fil angiven)
    if scope_file:
        run_cmd(f"cat {scope_file} | httpx -silent > scope_alive.txt", cwd=target_dir)

        # 13. FFUF-liknande endpoint discovery med roterande User-Agent
    seclist_path = os.path.expanduser(
        "~/Documents/SecLists/Discovery/Web-Content/common.txt"
    )
    if os.path.exists(seclist_path):
        asyncio.run(ffuf_like_discovery(target, seclist_path, USER_AGENTS))
    else:
        print(f"[-] Hittar inte SecLists wordlist: {seclist_path}")

    print("\n[+] Done!")
    print(f"- XSS: {subprocess.getoutput('wc -l < xss_results.txt')} rader")
    print(f"- Nuclei: {subprocess.getoutput('wc -l < nuclei_results.txt')} rader")
    print(f"- Redirects: {subprocess.getoutput('wc -l < redirect_check.txt')} rader")
    print(f"- JS-issues: {subprocess.getoutput('wc -l < js_issues.txt')} rader")
    print(
        f"- Secrets in URL: {subprocess.getoutput('wc -l < secrets_in_urls.txt')} rader"
    )


# CLI-argument
parser = argparse.ArgumentParser(description="L4 Recon Tool")
parser.add_argument("target", help="target domain")
parser.add_argument(
    "--subdomains", action="store_true", help="Include subdomain scan"
)
parser.add_argument("--scope", help="Fil med scope-domäner att scanna")
parser.add_argument("--skip-passive", action="store_true", help="Skip passive recon")


args = parser.parse_args()
recon(args.target, include_subdomains=args.subdomains, scope_file=args.scope, skip_passive=args.skip_passive)
