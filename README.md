# nullbinder #

this tools allow you to exploit and extract informations from misconfigured LDAP directory that allow null bind and null based searches

## installation ##

```bash
virtualenv venv
source venv/bin/activate
pip install python-ldap
```

## usage ##
```bash
usage: nullbinder.py [-h] [--host HOST] [--port PORT] [--host-file HOST_FILE]
                     out

Test an LDAP server for null bind, base dn, and dump the content.

positional arguments:
  out                   output directory, will be created if doesn't exist

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           host to scan (default: None)
  --port PORT           which port the ldap server is listenning on (default
                        to 389) (default: 389)
  --host-file HOST_FILE
                        provide a file containing list of host in the form
                        host:port (default: None)
```

Pull request are welcome !