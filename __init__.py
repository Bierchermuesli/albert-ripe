# -*- coding: utf-8 -*-

"""runs WHOIS-like Queries 

Synopsis: <trigger> ASN/Prefix"""

from albert import *
import requests
import re
import ipaddress


md_iid = "0.5"
md_version = "1.0"
md_id = "w"
md_name = "WHOIS"
md_description = "whois - a dns lookup tool with RIPE API"
md_license = "MIT"
md_url = "https://github.com/Bierchermuesli/albert-ripe"
md_maintainers = "@Bierchermuesli"
md_authors = "@Bierchermuesli"
md_lib_dependencies = ["request","ipaddress"]




class Plugin(QueryHandler): 
    
    def id(self):
        return md_id

    def name(self):
        return md_name

    def description(self):
        return md_description 
    
    
    def is_prefix(self,ip):
        try:
            ip = ipaddress.ip_network(ip,strict=False)
            debug(ip)
            
            return True
        except ValueError:
            return False
        except:
            return False


    def handleQuery(self,query):
    

        as_regex = re.compile('^(?as)(\d{2,6})$', re.IGNORECASE)


        """
        try to find any query type flag or @ask-another-resolver option?
        """
        qname = query.string.split()[0]


        if asn := as_regex.match(qname):
            asn = asn[0]
            r = requests.get('https://stat.ripe.net/data/as-overview/data.json?resource=as'+asn).json()

            debug("WHOIS checking ASN: "+ str(query))
            
            if r:
                if r['messages']:
                    query.add(Item(
                        id = md_id, 
                        text = str("whois "+ asn),
                        subtext = ': '.join(r['messages'][0]),
                    ))
                query.add(Item(
                    id = md_id, 
                    text = "AS{resource} - {holder}".format(**r['data']),
                    subtext = "is announced" if r['data']['announced'] else "not announced",
                    actions = [
                        Action("clip","Copy: AS{resource} - {holder}".format(**r['data']), lambda: setClipboardText("AS{resource} - {holder}".format(**r['data']))),
                        Action("url","Check PeeringDB",lambda: openUrl('https://www.peeringdb.com/search?q='+r['data']['resource']))
                        ]
                ))

            r = requests.get('https://stat.ripe.net/data/whois/data.json?resource=as'+asn).json()
            if r:
                for record in r['data']['records'][0]:
                    query.add(Item(
                    id = md_id, 
                    text =  "{key}: {value}".format(**record),
                    actions = [
                        Action("clip","copy {key}: {value}".format(**record), lambda: setClipboardText(record['value'])),
                        Action("clip","copy {value}".format(**record), lambda: setClipboardText(record['value'])),
                        ]
                    ))


        elif self.is_prefix(qname):
            r = requests.get('https://stat.ripe.net/data/prefix-overview/data.json?resource='+qname).json()
            
            debug("WHOIS checking IP: "+ str(query))

            if r:
                if r['messages']:
                    query.add(Item(
                        id = md_id, 
                        text = str("whois "+ qname),
                        subtext = ': '.join(r['messages'][0]),
                        # actions = [
                        #     Action("clip","Network {}".format(addr.network_address), lambda: setClipboardText(str(addr.network_address))),
                        #     ]
                    ))
                query.add(Item(
                    id = md_id, 
                    text = r['data']['resource'],
                    subtext = r['data']['type'],
                    # actions = [
                    #     Action("clip","Network {}".format(addr.network_address), lambda: setClipboardText(str(addr.network_address))),
                    #     ]
                ))
                for asn in r['data']['asns']:
                    query.add(Item(
                    id = md_id, 
                    text = "{asn}: {holder}".format(**asn),
                    actions = [
                        Action("clip","Copy {asn} {holder}".format(**asn), lambda: setClipboardText("{asn} {holder}".format(**asn))),
                        Action("clip","Copy {holder}".format(**asn), lambda: setClipboardText(asn['holder'])),
                        Action("clip","Copy AS{asn}".format(**asn), lambda: setClipboardText("AS"+asn['asn'])),
                        Action("clip","Copy {asn}".format(**asn), lambda: setClipboardText(asn['asn'])),
                        ]

                    ))
                
                r = requests.get('https://stat.ripe.net/data/whois/data.json?resource='+qname).json()
                if r:
                    for record in r['data']['records'][0]:
                        query.add(Item(
                        id = md_id, 
                        text =  "{key}: {value}".format(**record),
                    actions = [
                        Action("clip","copy {key}: {value}".format(**record), lambda: setClipboardText(record['value'])),
                        Action("clip","copy {value}".format(**record), lambda: setClipboardText(record['value'])),
                        ]

                        ))


