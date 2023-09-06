# guestlist
tool for identifying guest relationships between companies

```
*********************************************************************************************************

                            G U E S T L I S T  v1.00                  
                                                   
                           2023 @nyxgeek - TrustedSec                   
*********************************************************************************************************
usage: guestlist.py [-h] [-m] [-d] [-t] [-u] [-U] [-o] [-n] [-v] [-D] [-a] [-s] [-f] [-r] [-c]

optional arguments:
  -h, --help        show this help message and exit
  -m , --method     silent or graph (default:silent)
  -d , --domain     target domain name
  -t , --tenant     tenant name if known, otherwise specify domain and will lookup
  -u , --username   email address to target
  -U , --userfile   file containing email addresses
  -o , --output     file to write output to (default: output.log)
  -n, --no-db       disable logging to db
  -v, --verbose     enable verbose output
  -D, --debug       enable debug output
  -a , --access     fireprox AWS access_key
  -s , --secret     fireprox AWS secret key
  -f , --credfile   fireprox - file containing aws_secret and aws_key values
  -r , --region     fireprox AWS region
  -c , --command    fireprox command (create, delete, list)
```


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
