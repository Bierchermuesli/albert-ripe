# -*- coding: utf-8 -*-

"""runs WHOIS-like Queries 

Synopsis: <trigger> ASN/Prefix"""

from albert import *
import requests
import re
import ipaddress
import os


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





iconPath = os.path.dirname(__file__)+"/ripe_ncc.svg"


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

    def ripe_api(self,uri,resource):
        r = requests.get('https://stat.ripe.net/data/'+uri+'/data.json?resource='+resource).json()
        return r


    def handleQuery(self,query):
    
        ### For ASNs
        as_regex = re.compile('^(?:as)?(?P<asn>\d{2,6})$', re.IGNORECASE)
        results = []

        if search := as_regex.match(query.string):
            asn = search.group('asn')
            r = self.ripe_api("as-overview",'as'+asn)

            debug("WHOIS checking ASN: "+ str(asn))

            if r:
                if r['messages']:
                    query.add(Item(
                        id = md_id, 
                        icon=[iconPath],
                        text = r['messages'][0][0],
                        subtext = r['messages'][0][1]
                    ))
                query.add(Item(
                    id = md_id, 
                    text = "AS{resource} - {holder}".format(**r['data']),
                    subtext = "is announced" if r['data']['announced'] else "not announced",
                    icon=[iconPath],
                    actions = [
                        Action("clip","Copy: AS{resource} - {holder}".format(**r['data']), lambda: setClipboardText("AS{resource} - {holder}".format(**r['data']))),
                        Action("url","Check PeeringDB",lambda: openUrl('https://www.peeringdb.com/search?q='+r['data']['resource']))
                        ]
                ))
            


            r = self.ripe_api("whois",query.string)
            if r:
                for record in r['data']['records']:
                    whois_str=""
                    whois_substr=""
                    for line in record:
                        whois_str += "{key:15} {value}\n".format(**line)

                        #interesting fields for subtext
                        if line['key'] in ['as-name','org','source']:
                            whois_substr += "{value} ".format(**line)


                    query.add((Item(
                    id = md_id, 
                    text =  "{key}: {value}".format(**record[0]),
                    subtext = whois_substr,
                    icon= [os.path.dirname(__file__)+"/ripe_ncc-auth-num.svg"],
                    actions = [
                    Action("clip","copy {key} Object".format(**record[0]), lambda: setClipboardText(whois_str))
                    ])))

        ### For prefixes
        elif self.is_prefix(query.string):
            r = self.ripe_api("prefix-overview",query.string)
            
            debug("WHOIS checking IP: "+ str(query.string))

            if r:
                if r['messages']:
                    query.add(Item(
                        id = md_id, 
                        icon=[iconPath],
                        text = r['messages'][0][0],
                        subtext = r['messages'][0][1]
                    ))

                if r['see_also']:
                    for see_also in r['see_also']:
                        query.add(Item(
                            id = md_id, 
                            icon=[iconPath],
                            text = see_also['resource'],
                            subtext = "Relared as "+ see_also['relation'],
                            actions = [Action("clip","Copy {}".format(see_also['resource']), lambda: setClipboardText(see_also['resource']))]
                        ))
                    
                query.add(Item(
                    id = md_id, 
                    text = r['data']['resource'],
                    subtext = "is announced" if r['data']['announced'] else "not announced",
                    icon=[iconPath],
                    actions = [Action("clip","Copy {}".format(r['data']['resource']), lambda: setClipboardText(r['data']['resource']))]
                ))
                for asn in r['data']['asns']:
                    query.add(Item(
                    id = md_id, 
                    text = "AS{asn}: {holder}".format(**asn),
                    subtext = "announced by ^",
                    icon=[os.path.dirname(__file__)+"/ripe_ncc-auth-num.svg"],
                    actions = [
                        Action("clip","Copy AS{asn} {holder}".format(**asn), lambda: setClipboardText("{asn} {holder}".format(**asn))),
                        Action("clip","Copy {holder}".format(**asn), lambda: setClipboardText(asn['holder'])),
                        Action("clip","Copy AS{asn}".format(**asn), lambda: setClipboardText("AS"+asn['asn'])),
                        Action("clip","Copy {asn}".format(**asn), lambda: setClipboardText(asn['asn'])),
                        ]

                    ))


                #make a whois query
                r = self.ripe_api("whois",query.string)
                if r:
                    for record in r['data']['records']:
                        whois_str=""
                        whois_substr=""
                        for line in record:
                            whois_str += "{key:15} {value}\n".format(**line)

                            #interesting fields for subtext
                            if line['key'] in ['inetnum','netname','inetnum6','status','country','source']:
                                whois_substr += "{value} ".format(**line)

                        query.add(Item(
                        id = md_id, 
                        text =  "{key}: {value}".format(**record[0]),
                        subtext = whois_substr,
                        icon=[iconPath],
                        actions = [
                        Action("clip","copy {key} Object".format(**record[0]), lambda: setClipboardText(whois_str))
                        ]))

                    whois_str=""
                    whois_substr=""
                    for record in r['data']['irr_records']:
                        whois_str=""
                        whois_substr=""
                        actions = []
                        for line in record:
                            whois_str += "{key:15} {value}\n".format(**line)

                            #interesting fields for subtext
                            if line['key'] in ['origin']:              
                                whois_substr += "Origin AS{value}".format(**line)
                                actions.append(Action("clip","Copy 'AS{value}'".format(**line),lambda: setClipboardText("AS{value}".format(**line))))
                                actions.append(Action("clip","Copy '{value}'".format(**line),lambda: setClipboardText("{value}".format(**line))))


                        actions.append(Action("clip","copy {key} Object".format(**record[0]), lambda: setClipboardText(whois_str)))

                        query.add(Item(
                        id = md_id, 
                        text =  "{key}: {value}".format(**record[0]),
                        subtext = whois_substr,
                        icon=["xdg:copyq"],
                        actions = actions))