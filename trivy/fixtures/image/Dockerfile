# Deliberately vulnerable image used by CI and the l1/l3 demos: old pure-Python packages with published
# HIGH/CRITICAL CVEs that have fixed versions (requests 2.19.0 -> CVE-2018-18074, urllib3 1.23 -> CVE-2018-20060
# and others, Jinja2 2.10 -> CVE-2019-10906). Never deploy this.
FROM python:3.12-alpine
RUN pip install --no-cache-dir "requests==2.19.0" "urllib3==1.23" "Jinja2==2.10" "MarkupSafe==1.1.1"
CMD ["python", "-c", "print('vulnerable fixture')"]
