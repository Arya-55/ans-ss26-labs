# If line endings are causing trouble...
If you are using VS Code on Windows to edit this code, chances are that your eol encoding is set to CRLF.
For the bash script to run you need it to be LF though, because otherwise the Linux-VM won't understand it. 
Just changing that setting on that file doesn't really suffice however. You will need to tell git to always use LF by running the following commands in your local repo (**IMPORTANT:** Working Tree has to be clean, no changes present!):
```
git config core.autocrlf false

git rm --cached -r .         # Don’t forget the dot at the end

git reset --hard
```
The first command tells git to disable CRLF conversion, the other two update all files in the local repo to LF line endings.  
Additionally it might be sensible to set the eol of VS Code to  LF, aka "\n", to ensure that all new files are starting out with the correct line ending.