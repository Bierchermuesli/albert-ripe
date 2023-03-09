# -*- coding: utf-8 -*-
"""get details about prefixes, ASNs and runs WHOIS-like Queries from RIPE API

Synopsis: <trigger> ASN/Prefix"""

from albert import *
import requests
import re
import ipaddress
import os
from time import sleep

md_iid = "0.5"
md_version = "1.0"
md_id = "w"
md_name = "WHOIS"
md_description = "whois like lookup with RIPE API"
md_license = "MIT"
md_url = "https://github.com/Bierchermuesli/albert-ripe"
md_maintainers = "@Bierchermuesli"
md_authors = "@Bierchermuesli"
md_lib_dependencies = ["request","ipaddress"]


plugin_root = os.path.dirname(__file__)
icon_default = plugin_root+"/icon.svg"

as_regex = re.compile('^(?:as)?(?P<asn>\d{2,6})$', re.IGNORECASE)


famous_attributes = ['as-name','org','source','origin']
famous_objects = ['aut-num',"route","route6","inetnum","inet6num"]

class Plugin(QueryHandler): 
    
    def id(self):
        return md_id

    def name(self):
        return md_name

    def description(self):
        return md_description 
    
    def initialize(self):
        info("initialize Regexes")
    
    def is_prefix(self,ip):
        try:
            ip = ipaddress.ip_network(ip,strict=False)
            return True
        except ValueError:
            return False
        except:
            return False

    def ripe_api(self,uri,resource):
        user_agent = {'User-agent': 'Albert launcher'}
        try:
            r = requests.get('https://stat.ripe.net/data/'+uri+'/data.json?resource='+resource,headers = user_agent,timeout=1)
            if r.status_code == 200 and r.headers["content-type"].strip().startswith("application/json"):
                return r.json()
            else:
                return {'messages': [['Error', 'API said no?']],'status_code':500}
        except requests.ConnectionError as e:
            return {'messages': [['Offline?', str(e)]], 'status_code':500}
        except requests.exceptions.Timeout as e:
            return {'messages': [['Slow Down!', str(e)]], 'status_code':500}


#Handler thread threw ReadTimeout: HTTPSConnectionPool(host='stat.ripe.net', port=443): Read timed out. (read timeout=1)



    def handleQuery(self,query):

        if query.isValid:        
            ### For ASNs
            results = []
            asn = None
            # asn = self.as_regex.match(query.string)

            # if query.string.lower().startswith("as"):
            #     asn = int(query.string.lower().replace("as",""))

            #ASN Search
            if asn := as_regex.match(query.string):
                asn = int(asn.group('asn'))

                text = None

                #Check for any Private ASN
                if asn == 23456:
                    text = "AS_TRANS RFC6793"
                    subtext = "2 to 4 byte ASN migrations, should not appear in your path..."
                elif asn in range(64496,64511+1) or asn in range(65536,65551+1):
                    text = "RFC5398"
                    subtext = "AS Number Reservation for Documentation Use"
                    url = "https://www.rfc-editor.org/rfc/rfc5398"
                elif asn in range(64512,65534+1) or asn in range(4200000000,4294967294):
                    text = "RFC6996"
                    subtext = "AS Number Reservation for Private Use"
                    url = "https://www.rfc-editor.org/rfc/rfc6996"
                elif asn == 65535 or asn == 4294967295:
                    text = "RFC7300"
                    subtext = "Reservation of Last Autonomous System (AS) Numbers"
                    url = "https://www.rfc-editor.org/rfc/rfc7300"
                elif asn in range (65552,131071+1):
                    text = "IANA reserved"
                    subtext = "Not assignet (yet?)"
                    url = "https://www.iana.org/assignments/as-numbers/as-numbers.xhtml"

                #return if private ASN (no API query nessesary)
                if text:
                    debug("its a private ASN")
                    return query.add(Item(
                        id = "privateasn", 
                        text = text,
                        subtext = subtext,
                        icon=[icon_default],
                        actions = [
                            Action("clip","Copy '{}'".format(text), lambda: setClipboardText(text)),
                            Action("clip","Copy '{}'".format(subtext), lambda: setClipboardText(subtext)),
                            Action("url","Open RFC",lambda: openUrl(url))
                            ]))


                #short delay before we ask the API
                for number in range(50):
                    sleep(0.01)
                    if not query.isValid:
                        return

                
                debug("API Query for AS"+ str(asn))

                r = self.ripe_api("as-overview",'as'+str(asn))
                debug(r)
                if r:
                    if r['messages']:
                        for m in r['messages']:
                            query.add(Item(
                                id = md_id, 
                                icon=[icon_default],
                                text = m[0],
                                subtext = m[1],
                                actions = [Action("clip","Copy messsage", lambda: setClipboardText(m[1]))]
                            ))
                    #cancel further items or requests 
                    if r['status_code'] != 200:
                        return

                    #list some findings
                    if 'data' in r:
                        query.add(Item(
                            id = "as", 
                            text = "AS{resource} - {holder}".format(**r['data']),
                            subtext = "is announced" if r['data']['announced'] else "not announced",
                            icon=[icon_default],
                            actions = [
                                Action("clip","Copy: 'AS{resource} - {holder}'".format(**r['data']), lambda: setClipboardText("AS{resource} - {holder}".format(**r['data']))),
                                Action("url","Search PeeringDB",lambda: openUrl('https://www.peeringdb.com/search?q='+r['data']['resource']))
                                ]
                        ))
                        if 'block' in r['data']:
                            query.add(Item(
                            id = "asblock", 
                            text = "AS Block {resource} - {desc}".format(**r['data']['block']),
                            subtext = r['data']['block']['name'],
                            icon=[icon_default],
                            actions = [
                                Action("clip","Copy: Block Details", lambda: setClipboardText("Block {resource} - {desc}".format(**r['data']['block'])))
                                ]
                            ))
              

                    #do Whois if the above query was ok (no return)
                    w = self.ripe_api("whois",query.string)
                    if w:
                        debug(w)
                        
                        for record in w['data']['records']:
                            whois_str=""
                            whois_substr=""

                            #assing a icon on well known attributes
                            if record[0]['key'] in famous_objects:
                                record_icon = plugin_root+"/"+record[0]['key']+".svg"              
                            else:
                                record_icon = plugin_root+"/whois.svg"
                            
                            actions = []
                            for line in record:
                                whois_str += "{key:15} {value}\n".format(**line)

                                #look for interesting fields for subtext
                                if line['key'] in famous_attributes:
                                    whois_substr += "{value} ".format(**line)
                                    
                                    #some caching issues here?
                                    actions.append(
                                        Action("clip-"+line['key'],"Copy {key} '{value}'".format(**line), lambda: setClipboardText(line['value']))
                                    )
                            debug(actions)
                            actions.append(Action("clip-object","copy the whole WHOIS object", lambda: setClipboardText(whois_str)))

                            query.add((Item(
                                id = record[0]['key'], 
                                text =  "{key}: {value}".format(**record[0]),
                                subtext = whois_substr,
                                icon= [record_icon,],
                                actions = actions )))
                else:
                    return query.add(Item(
                        id = md_id, 
                        text = "not found?",
                        subtext = asn,
                        icon=[icon_default]))

            ### For prefixes
            elif self.is_prefix(query.string):
                r = self.ripe_api("prefix-overview",query.string)
                
                debug("WHOIS checking IP: "+ str(query.string))

                if r:
                    if r['messages']:
                        query.add(Item(
                            id = "info", 
                            icon=[icon_default],
                            text = r['messages'][0][0],
                            subtext = r['messages'][0][1]
                        ))

                    if r['see_also']:
                        for see_also in r['see_also']:
                            query.add(Item(
                                id = "seealso", 
                                icon=[icon_default],
                                text = see_also['resource'],
                                subtext = "Related as "+ see_also['relation'],
                                actions = [Action("clip","Copy {}".format(see_also['resource']), lambda: setClipboardText(see_also['resource']))]
                            ))
                        
                    query.add(Item(
                        id = "origin", 
                        text = r['data']['resource'],
                        subtext = "is announced" if r['data']['announced'] else "not announced",
                        icon=[icon_default],
                        actions = [Action("clip","Copy {}".format(r['data']['resource']), lambda: setClipboardText(r['data']['resource']))]
                    ))
                    for asn in r['data']['asns']:
                        query.add(Item(
                        id = "auth", 
                        text = "AS{asn}: {holder}".format(**asn),
                        subtext = "announced by ^",
                        icon=[plugin_root+"/aut-num.svg"],
                        actions = [
                            Action("clip","Copy AS{asn} {holder}".format(**asn), lambda: setClipboardText("{asn} {holder}".format(**asn))),
                            Action("clip","Copy {holder}".format(**asn), lambda: setClipboardText(asn['holder'])),
                            Action("clip","Copy AS{asn}".format(**asn), lambda: setClipboardText("AS"+str(asn['asn']))),
                            Action("clip","Copy {asn}".format(**asn), lambda: setClipboardText(asn['asn'])),
                            ]

                        ))


                    #make a whois query
                    r = self.ripe_api("whois",query.string)
                    if r:
                        for datatype in r['data']:
                        #loop over  all data elements 

                            if type(r['data'][datatype]) is list:
                                #loop over all list elements (like irr_records and records)
                                for record in r['data'][datatype]:
                                    if type(record) is list:
                                        # read all attributes from those records
                                        whois_str=""
                                        whois_substr=""
                                        actions = []

                                        #assing a icon for some wellknown objects
                                        debug("first key: "+record[0]['key'])
                                        if record[0]['key'] in famous_objects:
                                            record_icon = plugin_root+"/"+record[0]['key']+".svg"
                                        else:
                                            record_icon = plugin_root+"/whois.svg"
                                        
                                        for line in record:
                                            #setup a whois like string
                                            whois_str += "{key:15} {value}\n".format(**line)

                                            if line['key'] in famous_attributes:            
                                                #concate interesting attributes for subtext and action
                                                action_id = record[0]['key']+line['key']+line['value']
                                                debug("ActionID "+action_id)

                                                if line['key'] == 'origin':
                                                    #special kind for origin (route and route6) objects
                                                    whois_substr += "Origin AS{value} ".format(**line)
                                                    actions.append(Action(action_id,"Copy '{value}'".format(**line),lambda: setClipboardText(text=line['value'])))
                                                    value = "AS{value}".format(**line)
                                                    actions.append(Action(action_id,"Copy 'AS{value}'".format(**line),lambda: setClipboardText(text=value)))
                                                else:
                                                    whois_substr += "{value} ".format(**line)
                                                    value = line['value']
                                                    actions.append(Action(action_id,"Copy '{value}'".format(**line),lambda: setClipboardText(text=value)))
                                                actions.append(Action("foobar","copy something", lambda: setClipboardText(value)))


                                        actions.append(Action("clip-object","copy whole '{key}' Object".format(**record[0]), lambda: setClipboardText(whois_str)))

                                        query.add(Item(
                                        id = record[0]['key'],
                                        text =  "{key}: {value}".format(**record[0]),
                                        subtext = whois_substr,
                                        icon=[record_icon],
                                        actions = actions))
                                        del(actions)

                                    else:
                                        #some unknown list element
                                        query.add(Item(
                                        id = md_id, 
                                        text =  record,
                                        subtext = datatype,
                                        icon=[icon_default],
                                        actions = [Action("clip","copy"+record, lambda: setClipboardText(record))]))
                            else:
                                #some unknown string elements
                                query.add(Item(
                                id = md_id, 
                                text =  r['data'][datatype],
                                subtext = datatype,
                                icon=[icon_default],
                                actions = [Action("clip","copy"+r['data'][datatype], lambda: setClipboardText(r['data'][datatype]))]))

            else:
                    
                r = self.ripe_api("searchcomplete",query.string)
                info(r)
                debug("General Search: "+ str(query.string))
                for record in r['data']['categories']:

                    
                    for item in record['suggestions']:                       
                        actions = []    
                        actions.append(Action("clip","copy '{value}' Object".format(**item), lambda: setClipboardText(item['value'])))
                        if 'link' in item: 
                            actions.append(Action("url","Open URL",lambda: openUrl(item['link'])))

                        query.add(Item(
                        id = md_id, 
                        text =  item['value'],
                        subtext = item['description'],
                        completion = md_id+ " "+ item['value'], 
                        icon=[icon_default],
                        actions = actions))