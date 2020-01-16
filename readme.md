## Description
Simple firewall for Illumio that accepts or rejects packets based on given rules. 

## Requirements
The only library needed to be installed is Pandas. The ipaddress module is built into Python 3.3+.

## Explanation of code
I split the rules into 4 different lists (one for each combination of direction and protocol) to increase speed when checking rules at the expense of slightly more storage space. I made independent funcions for checking if the given values were valid ips and valid ports. 

In terms of next steps, the rules could be stored in a structured database. There could also be caching for quicker checking of more commonly used rules. A tree approach (interval trees) may also be used to solve this problem.

## Testing
I did not have time to test in depth, but I checked edge cases to make sure the rules with ranges were working as expected.

## Resources used
https://docs.python.org/3/library/ipaddress.html
https://stackoverflow.com/questions/16476924/how-to-iterate-over-rows-in-a-dataframe-in-pandas#comment82152649_16476974
https://docs.python.org/3/library/ipaddress.html