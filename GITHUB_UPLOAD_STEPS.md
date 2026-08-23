# How to upload this project to GitHub

Everything is prepared in the `linux-log-analysis-siem/` folder. Total size is
well under GitHub's limits, so the browser upload works — no command line required.

---

## Option A — Browser upload (easiest, no Git needed)

1. Go to **github.com** → click **+** (top right) → **New repository**
2. Fill in:
   - **Repository name:** `linux-log-analysis-siem`
   - **Description:** `SOC lab: manual triage, Python automation, and Splunk SIEM analysis of Linux authentication logs`
   - **Public** (recruiters need to see it)
   - Do **not** tick "Add a README" — you already have one
3. Click **Create repository**
4. On the empty repo page, click **uploading an existing file**
5. Drag the **contents** of the `linux-log-analysis-siem` folder in — not the folder
   itself. Drag the `README.md`, `.gitignore`, and the `docs`, `scripts`, `splunk`,
   `data`, `output`, and `screenshots` folders together.
6. Wait for all files to finish uploading (the screenshots take longest)
7. Commit message: `Initial commit - Linux log analysis, automation, and SIEM project`
8. Click **Commit changes**

---

## Option B — GitHub Desktop

1. Install GitHub Desktop and sign in
2. **File → New Repository**, name it `linux-log-analysis-siem`
3. Copy everything from the `linux-log-analysis-siem` folder into the repository folder
4. Enter a commit summary → **Commit to main** → **Publish repository** (untick "Keep this code private")

---

## Option C — Command line

```bash
cd linux-log-analysis-siem
git init
git add .
git commit -m "Initial commit - Linux log analysis, automation, and SIEM project"
git branch -M main
git remote add origin https://github.com/<your-username>/linux-log-analysis-siem.git
git push -u origin main
```

---

## After uploading — do these three things

They take two minutes and make a real difference to how the repo reads.

**1. Add topics.** On the repo page, click the gear icon beside **About** and add:

```
cybersecurity  soc-analyst  splunk  siem  log-analysis
python  incident-response  blue-team  threat-detection
```

**2. Add the description** in that same panel:

> SOC lab: manual triage, Python automation, and Splunk SIEM analysis of Linux authentication logs — including an incident write-up of a 47-source SSH brute-force campaign.

**3. Pin the repository** to your profile: go to your profile page → **Customize your pins** → tick this repo.

---

## Putting it on your resume and LinkedIn

**Resume bullet:**

> Analysed 2,000 Linux authentication log entries across three tooling stages (manual triage, Python automation, Splunk SIEM), identifying a 47-source SSH brute-force campaign in which 94.4% of attempts targeted the root account; documented root cause, remediation, and a detection coverage gap that would have caused 490 events to go undetected.

**LinkedIn "Projects" section:** use the repo URL and the first two paragraphs of the README as the description.

---

## What a recruiter will see

They will land on the README and, in about 20 seconds, register:

- **Key Findings table** — real numbers, not "I completed a tutorial"
- **Three objectives** — a clear progression from manual to automated to SIEM
- **Incident Analysis** — original work beyond the brief, which is the part that separates this from every other submission of the same lab
- **Secondary Finding** — a genuine detection-engineering insight (a rule that matched zero events because it was written for the wrong log format)

That last section is the strongest thing in the repository. If you get asked about
this project in an interview, that is the part to talk about.
