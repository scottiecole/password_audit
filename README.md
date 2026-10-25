"""
password_audit.py
A lightweight, DPAT-style (github.com/clr2of8/DPAT) password audit tool.
Combines an NTDS dump (secretsdump.py format) with a hashcat potfile of
cracked NT hashes and produces a report covering:
 
  - Total cracked hashes (including duplicate/shared-password accounts)
  - Percentage cracked
  - Unique cracked hashes / unique password count
  - Full list of cracked username:password pairs
  - Password complexity/character-class audit
  - Shared password groups (which accounts reuse the same password)
  - Top N most common cracked passwords
 
Prompts for: NTDS file, potfile, export file, include machine accounts,
include password history entries, include blank passwords, top N.
Exports a text report (same format as the console) plus a CSV of every
cracked account written alongside the export file:
    <export>_cracked.csv
 
Default export is <NTDS file name>_password_audit.txt next to the NTDS file
(e.g. /path/to/ntds.txt -> /path/to/ntds_password_audit.txt).
 
Notes:
  - Machine accounts (usernames ending in '$') are excluded by default,
    matching DPAT's default behavior.
  - Password history entries (user_history0, user_history1, ... from
    secretsdump -history) are excluded by default so they don't count as
    extra accounts. Include them to see old cracked passwords as well.
  - Account status isn't checked; disabled accounts are included.
  - $HEX[...] plaintexts in the potfile are decoded as UTF-8.
  - The report and CSV contain cleartext passwords - handle them accordingly.
"""
