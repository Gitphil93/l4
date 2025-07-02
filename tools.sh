#!/bin/bash

set -e

echo "[+] Uppdaterar system och installerar nödvändiga beroenden..."
sudo apt update -y
sudo apt install -y git curl wget unzip jq build-essential golang-go python3 python3-pip

echo "[+] Installerar Python-beroenden..."
pip3 install httpx

echo "[+] Installerar Go-verktyg..."
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/s0md3v/Arjun@latest

echo "[+] Installerar Amass..."
sudo snap install amass

echo "[+] Installerar LinkFinder..."
git clone https://github.com/GerbenJavado/LinkFinder.git ~/tools/LinkFinder
cd ~/tools/LinkFinder
pip3 install -r requirements.txt
sudo ln -sf "$(pwd)/linkfinder.py" /usr/local/bin/linkfinder

echo "[+] Installerar SecLists..."
git clone https://github.com/danielmiessler/SecLists.git ~/SecLists

echo "[+] Installerar färdigt. Kontrollera versioner:"

echo "ffuf: $(ffuf -version)"
echo "subfinder: $(subfinder -version)"
echo "dnsx: $(dnsx -version)"
echo "httpx: $(httpx -version)"
echo "katana: $(katana -version)"
echo "nuclei: $(nuclei -version)"
echo "dalfox: $(dalfox version)"
echo "gau: $(gau -version)"
echo "waybackurls: $(waybackurls -version || echo 'installerad')"
echo "arjun: $(arjun --version || echo 'installerad')"
echo "amass: $(amass -version)"
echo "LinkFinder: $(linkfinder --version || echo 'installerad')"
