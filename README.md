# guestlist
tool for identifying guest relationships between companies


## notes:

- supply email address, or file of email addresses of potential guest accounts
- supply either a domain name, or tenant name to test against
- (optional) specify silent vs graph-based enum
- (optional) specify aws creds for fireprox (only with silent enum currently)


## usage:


### silent method, no fireprox
```
./guestlist.py -d acmecomputercompany.com -U email_addresses.txt
```

### silent method with fireprox, using aws creds on command line
```
./guestlist.py -d acmecomputercompany.com -U email_addresses.txt -a "AKIAXXXXXXXXXXXXXXX" -s "xxxxxxxxxxxxxxxxx"
```

### silent method with fireprox, using aws cred file
```
./guestlist.py -d acmecomputercompany.com -U email_addresses.txt -f aws_config
```

### graph method, no fireprox
```
./guestlist.py -m graph -d acmecomputercompany.com -U email_addresses.txt
```

### graph method with fireprox, using aws cred file
```
./guestlist.py -m graph -d acmecomputercompany.com -U email_addresses.txt -f aws_config
```


## example:

```
./guestlist.py -d acmecomputercompany.com -U email_addresses.txt -f aws_config

*********************************************************************************************************

                            G U E S T L I S T  v1.00                  
                                                   
                           2023 @nyxgeek - TrustedSec                   
*********************************************************************************************************

Tenants Identified:
---------------------
acmecomputercompany

OneDrive hosts found:
---------------------
acmecomputercompany-my.sharepoint.com


++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

firprox is enabled
Creating => https://login.microsoftonline.com/...
[2023-09-04 16:22:58+00:00] (xxxxxxxxx) fireprox_microsoftonline => https://xxxxxxxxx.execute-api.us-east-2.amazonaws.com/fireprox/ (https://login.microsoftonline.com/)
[2023-09-04 16:22:58+00:00] (xxxxxxxxx) fireprox_microsoftonline: https://xxxxxxxxx.execute-api.us-east-2.amazonaws.com/fireprox/ => https://login.microsoftonline.com/
Initial fireprox endpoint has been configured


---------------------------------------------------------------------------------------------------------
amit.kumar@intranet.directory:acmecomputercompany:INVALID
michael.smith@intranet.directory:acmecomputercompany:INVALID
david.smith@intranet.directory:acmecomputercompany:INVALID
michael.johnson@intranet.directory:acmecomputercompany:INVALID
brian.smith@intranet.directory:acmecomputercompany:INVALID
jason.smith@intranet.directory:acmecomputercompany:INVALID
stephen.falken@intranet.directory:acmecomputercompany:VALID USERNAME
jose.garcia@intranet.directory:acmecomputercompany:INVALID
michael.williams@intranet.directory:acmecomputercompany:INVALID
```


The above output displays:

```
email_address:target_tenant:status
```



## Additional info:

Please check out the DEFCON 31 slide deck:

https://github.com/nyxgeek/track_the_planet

## Remediation

For remediation info (how to leave domains as Guests): https://learn.microsoft.com/en-us/azure/active-directory/external-identities/leave-the-organization


## SPECIAL THANKS AND SHOUTOUTS!

Thanks to @DrAzureAD, @thetechr0mancer, @ustayready !
references:
- https://aadinternals.com/post/desktopsso/ (@DrAzureAD - silent guest enum)
- https://github.com/blacklanternsecurity/TREVORspray (@thetechr0mancer)
- https://github.com/ustayready/fireprox (@ustayready)
