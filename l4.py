#!/bin/bash

source ~/recon-env/bin/activate
python3 path/to/your_script.py "$@"

import subprocess
import argparse
import os
import random
import asyncio
import httpx
import re
import json
from datetime import datetime
from collections import Counter
import statistics

RATE = 50
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

SEM_LIMIT = 10

async def semaphore_cmd(semaphore, cmd):
    async with semaphore:
        proc = await asyncio.create_subprocess_shell(cmd)
        await proc.communicate()

def run_cmd(cmd, cwd=None, output_file=None, skip_tools=None, tool_name=None):
    if skip_tools and tool_name in skip_tools:
        print(f"[+] Skipping {tool_name} due to user request.")
        return

    full_path = os.path.join(cwd if cwd else ".", output_file) if output_file else None
    if output_file and os.path.exists(full_path):
        print(f"[+] Skipping {tool_name} – output file already exists: {output_file}")
        return

    print(f"[+] Running: {cmd}")
    notify_discord(f"[L4 Recon] Running: {cmd}")
    try:
        subprocess.run(cmd, shell=True, cwd=cwd, check=True)
    except subprocess.CalledProcessError as e:
        notify_discord(f"[L4 Recon] Error running {cmd}: {e}")


def notify_discord(msg):
    webhook_url = os.getenv("DISCORD_WEBHOOK")
    if webhook_url:
        try:
            httpx.post(webhook_url, json={"content": msg})
        except Exception:
            pass

def run_ffuf(base_url, wordlist_path, output_path, skip_tools, user_agents, rate):
    if "ffuf" in skip_tools or os.path.exists(output_path):
        print(f"[+] Skipping ffuf – output file already exists: {output_path}")
        return

    cmd = (
        f"ffuf -u '{base_url.rstrip('/')}/FUZZ' "
        f"-w {wordlist_path} "
        f"-mc 200,500,401,403,301,302,429,400,405 -fw 1 -c -rate {rate} -of json -o {output_path} -H 'User-Agent: {random.choice(user_agents)}'"
    )
    run_cmd(cmd, tool_name="ffuf", output_file=output_path, skip_tools=skip_tools)


    notify_discord(f"[L4 Recon] Active bruteforce complete. {output_path} saved for {base_url}")


def run_extra_tools(target_dir, skip_tools):
    run_cmd("arjun -i urls_deduplicated.txt -oT arjun_params.txt -t 10", cwd=target_dir, output_file="arjun_params.txt", tool_name="arjun", skip_tools=skip_tools)

def fuzz_with_qsreplace(target_dir, payload_file):
    if not os.path.exists(payload_file):
        return

    with open(payload_file) as pf:
        payloads = [p.strip() for p in pf if p.strip()]

    results_file = os.path.join(target_dir, "qsreplace_fuzz_results.txt")

    with open(os.path.join(target_dir, "urls_with_params.txt")) as f:
        urls = [line.strip() for line in f if "?" in line]

    seen = set()
    with open(results_file, "w") as outf:
        for url in urls:
            param_names = re.findall(r'[?&]([^=&#]+)=', url)
            for param in param_names:
                for payload in payloads:
                    if (url, param, payload) in seen:
                        continue
                    seen.add((url, param, payload))

                    # Byt ut värdet på just denna param till payload
                    fuzzed_url = re.sub(rf'([?&]{re.escape(param)})=[^&#]*',
                                        rf'\1={payload}', url)

                    cmd = f"echo '{fuzzed_url}' | httpx -silent -status-code -content-length -follow-redirects"
                    proc = subprocess.Popen(cmd, shell=True, cwd=target_dir, stdout=subprocess.PIPE)
                    for line in proc.stdout:
                        decoded = line.decode().strip()
                        if decoded and not decoded.endswith("0"):
                            outf.write(f"{fuzzed_url} => {decoded}\n")

    notify_discord(f"[L4 Recon] Optimized parameter fuzzing complete.")

def detect_stack_with_wappalyzer(target_dir, skip_tools):
    notify_discord(f"[L4 Recon] Detecting stack with Wappalyzer.")
    tech_file = os.path.join(target_dir, "tech_stack.json")
    htmlprobe_cmd = f"cat urls_deduplicated.txt | httpx -silent -probe -tech-detect -json > tech_stack.json"

    run_cmd(htmlprobe_cmd, cwd=target_dir, tool_name="wappalyzer", output_file="tech_stack.json")

    tech_stack = set()
    try:
        with open(tech_file) as f:
            for line in f:
                try:
                    data = json.loads(line)
                    techs = data.get("technologies", [])
                    for t in techs:
                        tech_stack.add(t.lower())
                except Exception:
                    pass
    except FileNotFoundError:
        return []
    notify_discord(f"[L4 Recon] Detecting stack with Wappalyzer: {tech_stack}")
    return list(tech_stack)

def choose_stack_wordlists(tech_stack):
    lists = []
    tech_map = {
        "php": "~/Documents/SecLists/Discovery/Web-Content/php.txt",
        "wordpress": "~/Documents/SecLists/Discovery/Web-Content/CMS/wordpress.fuzz.txt",
        "asp.net": "~/Documents/SecLists/Discovery/Web-Content/IIS.fuzz.txt",
        "umbraco": "~/Documents/SecLists/Discovery/Web-Content/CMS/Umbraco.fuzz.txt",
        "django": "~/Documents/SecLists/Discovery/Web-Content/CMS/Django.txt",
        "drupal": "~/Documents/SecLists/Discovery/Web-Content/CMS/Drupal.txt",
    }
    for tech, path in tech_map.items():
        if tech in tech_stack:
            lists.append(path)
    return lists

def passive_recon(target, skip_tools):
    target_dir = f"l4-recon/{target}"
    os.makedirs(target_dir, exist_ok=True)
    notify_discord(f"[L4 Recon] Starting passive recon at {datetime.now()}")
    run_cmd(f"gau {target} | tee urls_raw.txt", cwd=target_dir, output_file="urls_raw.txt", tool_name="gau", skip_tools=skip_tools)
    run_cmd(f"waybackurls {target} >> urls_raw.txt", cwd=target_dir, output_file="urls_raw.txt", tool_name="waybackurls", skip_tools=skip_tools)
    run_cmd("sort -u urls_raw.txt > urls_all.txt", cwd=target_dir, output_file="urls_all.txt", tool_name="sort", skip_tools=skip_tools)
    run_cmd("cat urls_all.txt | grep '=' | grep -vE '\\.(jpg|jpeg|png|gif|svg|css|js|woff|ico)(\\?|$)' | grep -v '#' | grep -Ev '[\\{\\}\\[\\]<>\\|]' | grep -E '^https?://' | sort -u > urls_with_params.txt", cwd=target_dir, output_file="urls_with_params.txt", tool_name="param_filter", skip_tools=skip_tools)
    run_cmd("cat urls_with_params.txt | tr -cd '\\11\\12\\15\\40-\\176' | sed -E 's/([?&][^=&#]+)=?[^&#]*/\\1=VAR/g' | sort -u > urls_normalized.txt", cwd=target_dir, output_file="urls_normalized.txt", tool_name="normalize", skip_tools=skip_tools)
    
    deduplicate_similar_urls(
    os.path.join(target_dir, "urls_normalized.txt"),
    os.path.join(target_dir, "urls_deduplicated.txt"),
    target
)            
 
    run_cmd("cat urls_deduplicated.txt | grep '\\.js' | sort -u > js_files.txt", cwd=target_dir, output_file="js_files.txt", tool_name="js_filter", skip_tools=skip_tools)
    run_cmd("cat js_files.txt | xargs -I@ curl -s @ | linkfinder -i stdin -o cli > endpoints_from_js.txt", cwd=target_dir, output_file="endpoints_from_js.txt", tool_name="linkfinder", skip_tools=skip_tools)            
    run_cmd("katana -list urls_deduplicated.txt -jc -o katana_endpoints.txt", cwd=target_dir, output_file="katana_endpoints.txt", tool_name="katana", skip_tools=skip_tools)
   
    run_cmd("dalfox file urls_deduplicated.txt --only-poc r -o xss_results.txt", cwd=target_dir, output_file="xss_results.txt", tool_name="dalfox", skip_tools=skip_tools)
    run_cmd("nuclei -l urls_deduplicated.txt -headless -iserver https://server-two-rho.vercel.app -o nuclei_results.txt", cwd=target_dir, output_file="nuclei_results.txt", tool_name="nuclei", skip_tools=skip_tools)
    run_cmd("cat urls_all.txt | httpx -silent -status-code -title -tech-detect -web-server -o headers_scan.txt", cwd=target_dir, output_file="headers_scan.txt", tool_name="httpx", skip_tools=skip_tools)

    run_cmd("grep -Eoi '([a-z0-9_-]*key|token|secret)[=:][^&]+' urls_all.txt | tee secrets_in_urls.txt", cwd=target_dir, output_file="secrets_in_urls.txt", tool_name="secrets", skip_tools=skip_tools)
    run_cmd("cat js_files.txt | xargs -I@ curl -s @ > js_combined.js", cwd=target_dir, output_file="js_combined.js", tool_name="js_download", skip_tools=skip_tools)
    run_cmd(r"grep -Ei 'localStorage|document\\.cookie|innerHTML|document\\.write|dangerouslySetInnerHTML|fetch\\(|XMLHttpRequest|feature[_-]?flags?|featureflag|experiment|admin|administrator' js_combined.js > js_issues.txt", cwd=target_dir, output_file="js_issues.txt", tool_name="js_issues", skip_tools=skip_tools)
    run_extra_tools(target_dir, skip_tools)
    
def deduplicate_similar_urls(input_file, output_file, target):
    seen_templates = set()
    with open(input_file) as f:
        urls = f.readlines()

    with open(output_file, "w") as out:
        for url in urls:
            url = url.strip()
            normalized = re.sub(r"=[^&#]+", "=VAL", url)
            normalized = re.sub(r"/\d+", "/NUM", normalized)  # numeriska paths
            normalized = re.sub(r"/[a-zA-Z0-9_-]{5,}", "/STR", normalized)  # slugs
            if normalized not in seen_templates:
                seen_templates.add(normalized)
                out.write(url + "\n")
                
                
    #notify_discord(f"[L4 Recon] Passive recon finished for {target} at {datetime.now()}")
    
async def run_full_recon(sub, args, skip_tools):
    target_dir = f"l4-recon/{sub}"
    os.makedirs(target_dir, exist_ok=True)

    passive_recon(sub, skip_tools)

    default_lists = [
        os.path.expanduser("~/Documents/SecLists/Discovery/Web-Content/common.txt"),
        os.path.expanduser("~/Documents/SecLists/Discovery/Web-Content/raft-large-directories.txt"),
        os.path.expanduser("~/Documents/SecLists/Discovery/Web-Content/raft-large-files.txt"),
        os.path.expanduser("~/Documents/SecLists/Discovery/Web-Content/env.txt")
    ]
    tech_stack = detect_stack_with_wappalyzer(target_dir, skip_tools)
    tech_lists = choose_stack_wordlists(tech_stack)
    all_lists = tech_lists + default_lists

    base_url = f"https://{sub}"
    for wl in all_lists:
        wl = os.path.expanduser(wl)
        output_path = os.path.join(target_dir, os.path.basename(wl) + "_ffuf.json")
        notify_discord(f"[L4 Recon] Running Ffuf on {sub} with {wl}")
        run_ffuf(base_url, wl, output_path, skip_tools, USER_AGENTS, RATE)

    if args.payloads:
        fuzz_with_qsreplace(target_dir, args.payloads)
        
def subdomain_enum(target_root_dir, target, skip_tools):
    subfinder_out = os.path.join(target_root_dir, "subfinder.txt")
    amass_out = os.path.join(target_root_dir, "amass.txt")
    dnsx_out = os.path.join(target_root_dir, "subdomains.txt")

    run_cmd(f"subfinder -d {target} -silent -all -o {subfinder_out}", cwd=target_root_dir, output_file="subfinder.txt", tool_name="subfinder", skip_tools=skip_tools)
    run_cmd(f"amass enum -passive -d {target} -o {amass_out}", cwd=target_root_dir, output_file="amass.txt", tool_name="amass", skip_tools=skip_tools)

    combined_path = os.path.join(target_root_dir, "combined_subs.txt")
    with open(combined_path, "w") as combined:
        if os.path.exists(subfinder_out):
            with open(subfinder_out) as f:
                combined.writelines(f.readlines())
        if os.path.exists(amass_out):
            with open(amass_out) as f:
                combined.writelines(f.readlines())
                
         

    run_cmd(f"cat combined_subs.txt | sort -u | dnsx -silent -retries 2 -o {dnsx_out}", cwd=target_root_dir, output_file="subdomains.txt", tool_name="dnsx", skip_tools=skip_tools)
    if os.path.getsize(dnsx_out) == 0:
    print("[!] No subdomains found, exiting.")
    return None  
    return dnsx_out        
    

async def get_live_subdomains(domains):
    tasks = []
    for d in domains:
        cmd = f"echo https://{d} | httpx -status-code -silent"
        tasks.append(asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE))

    live = []
    for proc in await asyncio.gather(*tasks):
        out, _ = await proc.communicate()
        if out:
            live.append(out.decode().strip().replace("https://", ""))

    return live

async def bounded_run(semaphore, sub, args, skip_tools):
    async with semaphore:
        await run_full_recon(sub, args, skip_tools)

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Target domain, e.g. example.com")
    parser.add_argument("-s", "--subdomains", action="store_true", help="Enumerate and scan all subdomains")
    parser.add_argument("--skip", help="Comma-separated list of tools to skip", default="")
    parser.add_argument("--payloads", help="File with payloads for fuzzing parameters", default=None)
    args = parser.parse_args()

    skip_tools = set(args.skip.split(",")) if args.skip else set()
    target_root_dir = f"l4-recon/{args.target.strip()}"
    os.makedirs(target_root_dir, exist_ok=True)

    if args.subdomains:
        subdomain_path = subdomain_enum(target_root_dir, args.target, skip_tools)
        if subdomain_path is None:
            return
        with open(subdomain_path) as f:
            subs = [line.strip() for line in f if line.strip()]
        subdomains = await get_live_subdomains(subs)
    else:
        subdomains = [args.target.strip()]

    semaphore = asyncio.Semaphore(SEM_LIMIT)
    tasks = [bounded_run(semaphore, sub, args, skip_tools) for sub in subdomains]

    await asyncio.gather(*tasks)



if __name__ == "__main__":
    asyncio.run(main())
