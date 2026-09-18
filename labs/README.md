# Lab source trees (Juice Shop, DVWA)

Clone the authorised teaching-app source here so WebSET can run static analysis:

```powershell
python scripts/fetch-lab-sources.py
```

or

```powershell
.\scripts\fetch-lab-sources.ps1
```

That creates `labs/juice-shop` and `labs/dvwa`. The clones are gitignored.

Static analysis is skipped when these directories are missing; dynamic analysis and the training catalog still run.
