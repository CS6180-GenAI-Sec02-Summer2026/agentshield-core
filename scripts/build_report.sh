#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
report_dir="${repo_root}/docs/report"

cd "${report_dir}"
pandoc agentshield_report.md \
  --standalone \
  --toc \
  --toc-depth=1 \
  --pdf-engine=pdflatex \
  --include-in-header=report_header.tex \
  -V geometry:top=1in \
  -V geometry:bottom=1.3in \
  -V geometry:left=1in \
  -V geometry:right=1in \
  -o agentshield_report.tex

pdflatex -interaction=nonstopmode -halt-on-error agentshield_report.tex
pdflatex -interaction=nonstopmode -halt-on-error agentshield_report.tex
pdflatex -interaction=nonstopmode -halt-on-error agentshield_report.tex
rm -f agentshield_report.aux agentshield_report.log agentshield_report.out agentshield_report.toc
