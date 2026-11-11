# Gig assistant

A small helper for picking up online freelance jobs with AI help, with you in charge.

You find a job post (Craigslist, Upwork, anywhere) and paste it in. The script:

1. flags common scam signals,
2. scores how well the job suits AI-assisted work,
3. drafts a reply for you to edit and send yourself.

It does not browse, scrape, apply, or message anyone. No installs needed, just Python 3.

## Use

```bash
python3 gig_assistant.py post.txt              # a saved post
python3 gig_assistant.py                       # paste, then Ctrl-D
python3 gig_assistant.py post.txt --name "Sam" # sign the draft
python3 gig_assistant.py post.txt --json       # machine-readable
```

Try it on the samples:

```bash
python3 gig_assistant.py examples/good_post.txt
python3 gig_assistant.py examples/scam_post.txt
```

## Workflow

1. Find a post and run it through the script.
2. Go through `CHECKLIST.md` by hand. The script only matches known patterns.
3. Edit the draft reply and send it yourself.
4. When you land the job, bring the brief to Claude to do the heavy lifting.
5. Check the work, deliver it, and get paid through a method with a paper trail.

## Limits

The scam check and fit score are keyword rules, so they will miss things and sometimes
flag harmless posts. Treat the output as a first pass.
