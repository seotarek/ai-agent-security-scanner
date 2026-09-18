import sys
import argparse
from .core import SecurityScanner

def main():
    parser = argparse.ArgumentParser(description="AI Agent Security Scanner CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a single prompt or file for security threats")
    scan_parser.add_argument("prompt", nargs="?", help="Direct prompt text to evaluate")
    scan_parser.add_argument("--file", "-f", help="Path to text file containing prompt")

    # Benchmark command
    subparsers.add_parser("benchmark", help="Run adversarial benchmark suite")

    args = parser.parse_args()
    scanner = SecurityScanner()

    if args.command == "scan":
        content = ""
        if args.file:
            with open(args.file, "r", encoding="utf-8") as f:
                content = f.read()
        elif args.prompt:
            content = args.prompt
        else:
            print("Error: Provide either a prompt argument or --file")
            sys.exit(1)

        result = scanner.scan_prompt(content)
        print("========================================")
        print(" AI AGENT SECURITY SCAN REPORT")
        print("========================================")
        print(f"Status:     {'[SAFE]' if result.is_safe else '[VULNERABLE]'}")
        print(f"Risk Score: {result.risk_score} / 100")
        if not result.is_safe:
            print(f"Category:   {result.category}")
            print("Matched Rules:")
            for r in result.matched_rules:
                print(f"  - {r}")
            if result.decoded_payloads:
                print(f"Decoded Payloads Found: {len(result.decoded_payloads)}")
            sys.exit(2)
        else:
            print("No injection patterns or adversarial signatures detected.")
            sys.exit(0)

    elif args.command == "benchmark":
        from .benchmarks import run_benchmark
        run_benchmark(scanner)

if __name__ == "__main__":
    main()
