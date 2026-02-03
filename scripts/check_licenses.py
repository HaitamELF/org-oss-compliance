import json, glob, re, sys, os, datetime

DENYLIST_FILE = os.environ.get("DENYLIST_FILE", "policy/licenses-denylist.txt")
EXCEPTIONS_FILE = os.environ.get("EXCEPTIONS_FILE", ".compliance/exceptions.json")

def load_denylist():
  deny = []
  with open(DENYLIST_FILE, "r", encoding="utf-8") as f:
    for line in f:
      line = line.strip()
      if line and not line.startswith("#"):
        deny.append(line)
  return set(deny)

def load_exceptions():
  if not os.path.exists(EXCEPTIONS_FILE):
    return {}
  data = json.load(open(EXCEPTIONS_FILE, "r", encoding="utf-8"))
  exc = {}
  today = datetime.date.today()
  for e in data.get("exceptions", []):
    exp = datetime.date.fromisoformat(e["expires"])
    if exp >= today:
      exc[e["purl"]] = e
  return exc

def iter_components(bom: dict):
  for c in (bom.get("components") or []):
    yield c

def get_license_id(component: dict):
  licenses = component.get("licenses") or []
  for L in licenses:
    if not isinstance(L, dict):
      continue
    licobj = L.get("license") or {}
    lic = licobj.get("id") or licobj.get("name")
    if lic:
      return str(lic).strip()
  return None

def main():
  deny = load_denylist()
  exceptions = load_exceptions()

  sboms = sorted(set(
    glob.glob("sbom-*.json") +
    glob.glob("**/sbom-*.json", recursive=True) +
    glob.glob("**/bom.json", recursive=True)
  ))

  if not sboms:
    print("No SBOM files found. (This is non-blocking.)")
    return 0

  findings = []
  for fp in sboms:
    try:
      bom = json.load(open(fp, "r", encoding="utf-8"))
    except Exception:
      continue

    for c in iter_components(bom):
      lic = get_license_id(c)
      if not lic:
        continue

      purl = (c.get("purl") or "").strip()
      if lic in deny:
        if purl and purl in exceptions:
          continue
        findings.append({
          "name": c.get("name"),
          "version": c.get("version"),
          "license": lic,
          "purl": purl,
          "sbom": fp
        })

  if findings:
    out = "forbidden-licenses.json"
    json.dump(findings, open(out, "w", encoding="utf-8"), indent=2)
    print("Forbidden licenses detected:")
    for f in findings[:200]:
      print(f"- {f['name']}@{f['version']} | {f['license']} | {f['purl']} | {f['sbom']}")
    print(f"Report: {out}")
    return 1

  print("OK: no forbidden licenses found.")
  return 0

if __name__ == "__main__":
  raise SystemExit(main())