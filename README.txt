--- README ---
Name: Steven Lee
UTID: scl346
CSID: scl346
Class: CS361
Project 5 PasswordCrack

I implemented a breadth-first algorithm that starts with fewest mangles and then increases the mangles.
This algorithm basically checks for the simplest passwords so can quickly find passwords that have 0
mangles or 1 mangle.

First, it checks the input dictionary fully to see if the password is one of those words. A mangle counter
keeps track of how many mangles to perform. That way, on the first mangle, it knows to only mangle once, and
on future mangles, it knows not to check previously checked single mangles and so on. I also included a 
TIMER_LIMIT constant that will stop checking for a certain password after 2 minutes without success. If the goal
is to crack as many passwords in a short time, this prevents it from going too deep into one password.

For passwd1.txt:
passwords cracked = 18, time to crack = 248406ms (248 seconds)
- the two passwords that were not cracked took 240 seconds to reach the limit, both required at least 3 mangles
- one or 0 mangled passwords yielded very small amounts (0-151ms)

For passwd2.txt
passwords cracked = 16, time to crack = 490321ms (490 seconds)
- uncracked passwords took 480 seconds to reach the limit