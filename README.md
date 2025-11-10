# The LinPrivEsc Bible
A personal Linux privilege escalation I have cooked up for near a year now that I hope serves you like it has me : )

I started this as a set of personal, messy notes while doing the Tiberius priv-esc course, OSCP challenge labs and a bunch of HTB/THM/PG/VHL boxes. Over time as I gained more doamin specific knowledge be it from CTFs, finding real world CVEs or from real engagements; The notes grew beyond their original use and that Im really proud of :3

Why do I call this the bible? Well I hated the generic “look for config files for creds” or "Overwrite a file executed by privlidged process" line on most cheatsheets that made you feel either:
  - Dumb cuz you couldnt figure what the author meant by that one sentence and linpeas isnt giving you any breaks either OR 
  - So vague that, I feel at least, mislead you in your quest for root

And so I wrote commands for creds in the respective configuration files of the common services (Apache, MySQL, Tomcat, WordPress, etc.), one liners to discover Shared object files that are loaded by a binary that are writeable to your user, running init.d scripts writeable to your user, different ways to priv esc when your a member of an exotoic group(think disk or adm group) and much more! 

For every pattern I try to give a concise check (usually a one-liner) and a one- or two-line abuse command you can run straight away. I find that to be the most helpful as its easier for you to run commands that "ask" one question, for example are there any startup scripts that I can write to, and either the files are returned or nothing is(meaning no there isnt). 

I add stuff as I find it new CVEs, misconfigs, or anything that wasted time for me in the past such that I never have to spend time/effort finding and abusing it again. You can check out the projects commit history if you want recent examples for a CVE I found that I turned into a one liner.

A qucik tip about the project is that it’s big and hyper specific, so if you’re a beginner it can feel overwhelming. I suggest doing a fast read through, then use it as a checklist while going through your workflows. That way you have a rough idea of where everything is and minimize lost time.

This is for learning, CTFs and authorised testing only. You most defo shouldnt use it on systems you don’t have permission to test and dont do anything youre not sure how itll play out : ) 

Open an issue or Pull Request if you have any suggestions on improvements and making this repo better/more useful for the community. 

