import os
import logging
import requests
import sys
import argparse
import threading
import time
import json
import csv
import re
from tqdm import tqdm
from colorama import init as colorama_init, Fore, Style
from rich.console import Console
from rich.markdown import Markdown

colorama_init()
console = Console()

logger = logging.getLogger(__name__)
handlers = [logging.StreamHandler()]
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=handlers
)
if '--debug' in sys.argv:
    logger.setLevel(logging.DEBUG)

loading = True

def show_progress():
    with tqdm(total=100, desc="Analyzing", bar_format="{l_bar}{bar} | Elapsed: {elapsed}") as pbar:
        while loading:
            for _ in range(10):
                if not loading:
                    break
                pbar.update(1)
                time.sleep(0.1)
            pbar.n = 0
            pbar.last_print_n = 0
            pbar.refresh()

def with_progress(fn):
    global loading
    loading = True
    thread = threading.Thread(target=show_progress)
    thread.start()
    try:
        return fn()
    finally:
        loading = False
        thread.join()

def read_directory(path):
    result = []
    for root, _, files in os.walk(path):
        for filename in files:
            full_path = os.path.join(root, filename)
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    result.append(f"\n=== File: {os.path.relpath(full_path, path)} ===")
                    for i, line in enumerate(lines, start=1):
                        result.append(f"{i}: {line.rstrip()}")
            except Exception as e:
                logger.warning(f"Could not read file {full_path}: {e}")
    return '\n'.join(result)

class AI:
    def __init__(self, model, path, prompt_file='prompt.txt', completions_file='completions.txt'):
        self.model = model
        self.path = path
        self.prompt = self._read_file(prompt_file)
        self.completions = self._read_file(completions_file)

    def _read_file(self, filepath):
        try:
            with open(filepath, 'r') as f:
                return ' '.join(f.read().split())
        except FileNotFoundError:
            logger.error(f"File not found: {filepath}")
            return ""

    def run_model(self):
        full_prompt = f"{self.prompt}\n\n\n{read_directory(self.path)}\n\n\n{self.completions}"
        model_name = self.model.lower()

        def get_key(provider):
            key_attr = f"{provider}_api_key"
            key = getattr(self, key_attr, None)
            if not key:
                key = input(f"Enter your {provider} API key for model '{model_name}':\n").strip()
                setattr(self, key_attr, key)
            return key

        if model_name.startswith("openai"):
            api_key = get_key('openai')
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            data = {
                "model": self.model,
                "messages": [{"role": "user", "content": full_prompt}],
                "stream": False,
                "temperature": 0.7
            }

            def call_openai():
                response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=data)
                if response.ok:
                    return response.json()['choices'][0]['message']['content']
                else:
                    logger.error(f"OpenAI error {response.status_code}: {response.text}")
                    return None

            return with_progress(call_openai)

        elif model_name.startswith("claude"):
            api_key = get_key('claude')
            headers = {"x-api-key": api_key, "Content-Type": "application/json"}
            data = {
                "model": self.model,
                "messages": [{"role": "user", "content": full_prompt}],
                "stream": False,
                "temperature": 0.7
            }

            def call_claude():
                response = requests.post("https://api.anthropic.com/v1/messages", headers=headers, json=data)
                if response.ok:
                    return response.json().get('completion', None)
                else:
                    logger.error(f"Claude error {response.status_code}: {response.text}")
                    return None

            return with_progress(call_claude)

        elif model_name.startswith("gemini"):
            api_key = get_key('gemini')
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            data = {
                "contents": [{"parts": [{"text": full_prompt}]}],
                "generationConfig": {"temperature": 0.7, "maxOutputTokens": 1024}
            }
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"

            def call_gemini():
                response = requests.post(url, headers=headers, json=data)
                if response.ok:
                    return response.json()['candidates'][0]['content']
                else:
                    logger.error(f"Gemini error {response.status_code}: {response.text}")
                    return None

            return with_progress(call_gemini)

        elif model_name.startswith(("llama", "local", "qwen")):
            model_map = {
                "llama3.1": "llama3.1",
                "llama3.2": "llama3.2",
                "llama3.3": "llama3.3",
                "llama4": "llama4",
                "llama4:scout": "llama4:scout",
                "mistral": "mistral",
                "gemma3": "gemma3",
                "phi4": "phi4",
                "mixtral": "mixtral",
                "codegemma": "codegemma",
                "qwen2": "qwen2",
                "qwen2.5": "qwen2.5",
                "qwen2.5-coder:latest": "qwen2.5-coder:latest"
            }

            if self.model.lower() not in model_map:
                logger.error(f"Unsupported local model: {self.model}")
                return None

            model_id = model_map[self.model.lower()]
            url = "http://localhost:11434/api/generate"
            data = {"model": model_id, "prompt": full_prompt, "stream": False}

            def call_local():
                try:
                    response = requests.post(url, json=data)
                    if response.ok:
                        return response.json().get('response', None)
                    else:
                        logger.error(f"{model_id} error {response.status_code}: {response.text}")
                        return None
                except Exception as e:
                    logger.error(f"Exception with model '{model_id}': {e}")
                    return None

            return with_progress(call_local)

        else:
            logger.error(f"Model '{self.model}' is not supported.")
            return None

def parse_vulnerabilities(markdown_text):
    findings = []
    current = {}

    for line in markdown_text.splitlines():
        line = line.strip()
        if re.match(r'\d+\.\s+\*\*(.+?)\*\*', line):
            if current:
                findings.append(current)
                current = {}
            current['issue'] = re.sub(r'\d+\.\s+\*\*(.+?)\*\*', r'\1', line)
        elif line.startswith('- **Vulnerable Part**:'):
            current['code'] = line.split(':', 1)[1].strip()
        elif line.startswith('- **Explanation**:'):
            current['explanation'] = line.split(':', 1)[1].strip()
        elif line.startswith('- **File**:'):
            current['file'] = line.split(':', 1)[1].strip()
        elif line.startswith('- **Line**:'):
            current['line'] = line.split(':', 1)[1].strip()
    if current:
        findings.append(current)
    return findings

def save_json(findings, filename="vulnerabilities.json"):
    with open(filename, 'w') as f:
        json.dump(findings, f, indent=2)
    logger.info(f"Saved JSON output to {filename}")

def save_csv(findings, filename="vulnerabilities.csv"):
    if not findings:
        return
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=findings[0].keys())
        writer.writeheader()
        writer.writerows(findings)
    logger.info(f"Saved CSV output to {filename}")

def main():
    parser = argparse.ArgumentParser(description="🔐 AI Secure Code Review Tool")
    parser.add_argument('--model', required=True, help='Model name (e.g., openai/gpt-4, qwen2.5-coder:latest)')
    parser.add_argument('--folder', required=True, help='Folder path to analyze')
    parser.add_argument('--output-json', action='store_true', help='Save result to JSON')
    parser.add_argument('--output-csv', action='store_true', help='Save result to CSV')
    args = parser.parse_args()

    ai = AI(args.model, args.folder)
    result = ai.run_model()

    if result:
        print("\n" + Fore.GREEN + Style.BRIGHT + "🔎 Vulnerability Report\n" + Style.RESET_ALL)
        try:
            console.print(Markdown(result))
        except Exception:
            print(Fore.GREEN + result + Style.RESET_ALL)

        findings = parse_vulnerabilities(result)

        if args.output_json:
            save_json(findings)

        if args.output_csv:
            save_csv(findings)
    else:
        print(Fore.RED + "❌ No response or failed to analyze code." + Style.RESET_ALL)

if __name__ == "__main__":
    main()

