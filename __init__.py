# -*- coding: utf-8 -*-
"""get details about prefixes, ASNs and runs WHOIS-like Queries from RIPE API

yes, this code could be nicer...

Synopsis: <trigger> ASN/Prefix
"""

from albert import *
import requests
import re
import yaml
from ipaddress import ip_network, ip_address,IPv4Address,IPv6Address
import os
from time import sleep
from dns import resolver
from pathlib import Path


md_iid = "2.1"
md_version = "1.5"
md_id = "w"
md_name = "RIPE-Whois"
md_description = "whois like lookup with RIPE API"
md_license = "MIT"
md_url = "https://github.com/Bierchermuesli/albert-ripe"
md_maintainers = "@Bierchermuesli"
md_authors = "@Bierchermuesli"
md_lib_dependencies = ["request","ipaddress"]


class Plugin(PluginInstance, GlobalQueryHandler):

    icon_default = [f"file:{Path(__file__).parent}/icon.svg"]

    def __init__(self):
        GlobalQueryHandler.__init__(self,
                                    id=md_id,
                                    name=md_name,
                                    description=md_description,
                                    defaultTrigger='w ')
        PluginInstance.__init__(self, extensions=[self])

    def initialize(self):
        debug("initialize Regexes")
        self.as_regex = re.compile('^(?:as)?(?P<asn>\d{2,6})$', re.IGNORECASE)

        config_file = Path(__file__).parent.joinpath("config-defaults.yaml")
        debug('Load Default Config: '+str(config_file))
        default_config = self.load_yaml(config_file)

        config_file = self.configLocation.joinpath("config.yaml")
        debug("Load user_config (if any): "+ str(config_file))
        user_config = self.load_yaml(config_file)

        #simple config merge
        for k, v in default_config.items():
            if k in user_config:
                user_config[k].update(v)
            else:
                user_config[k] = v
        self.config = user_config

    def load_yaml(self,file):
        """ loads a yaml file - if exist"""
        if file.is_file():
            try:
                with open(file) as pointer:
                    return yaml.load(pointer, Loader=yaml.SafeLoader)
            except:
                return {}
        return {}

    def is_prefix_or_address(self,ip):
        try:
            ip = ip_address(ip)
            return ip
        except ValueError:
            #check if its a subnet
            try:
                ip = ip_network(ip,strict=False)
                return ip
            except ValueError:
                return False

    def ripe_api(self,uri,resource):
        headers = {'user_config-agent': 'Albert Launcher'}
        try:
            r = requests.get('https://stat.ripe.net/data/'+uri+'/data.json?resource='+resource,headers = headers,timeout=1)
            if r.status_code == 200 and r.headers["content-type"].strip().startswith("application/json"):
                return r.json()
            else:
                return {'messages': [['Error', 'API said no?']],'status_code':500}
        except requests.ConnectionError as err:
            return {'messages': [['Offline?', str(err)]], 'status_code':500}
        except requests.exceptions.Timeout as err:
            return {'messages': [['Slow Down!', str(err)]], 'status_code':500}

    def handleTriggerQuery(self,query):
        if query.isValid:

            # ====================
            # :: ASN Search
            # ====================
            if asn := self.as_regex.match(query.string):
                asn = int(asn.group('asn'))
                private = None

                #resolve any private Private ASN locally
                if asn in self.config['custom_as'].keys(): #in case we have some our local file
                    private = self.config['custom_as'][asn]['name']
                    subtext = self.config['custom_as'][asn]['info']
                    url = self.config['custom_as'][asn]['url']
                # next AS ranges are more handy than external yaml :)
                elif asn == 23456:
                    text = "AS_TRANS RFC6793"
                    subtext = "2 to 4 byte ASN migrations, should not appear in your path..."
                elif asn in range(64496,64511+1) or asn in range(65536,65551+1):
                    private = "RFC5398"
                    subtext = "AS Number Reservation for Documentation Use"
                    url = "https://www.rfc-editor.org/rfc/rfc5398"
                elif asn in range(64512,65534+1) or asn in range(4200000000,4294967294):
                    private = "RFC6996"
                    subtext = "AS Number Reservation for Private Use"
                    url = "https://www.rfc-editor.org/rfc/rfc6996"
                elif asn == 65535 or asn == 4294967295:
                    private = "RFC7300"
                    subtext = "Reservation of Last Autonomous System (AS) Numbers"
                    url = "https://www.rfc-editor.org/rfc/rfc7300"
                elif asn in range (65552,131071+1):
                    private = "IANA reserved"
                    subtext = "Not assignet (yet?)"
                    url = "https://www.iana.org/assignments/as-numbers/as-numbers.xhtml"

                #return if private ASN (do not ask any external API)
                if private:
                    return query.add(StandardItem(
                        id = "privateasn",
                        text = private,
                        subtext = subtext,
                        iconUrls=self.icon_default,
                        actions = [
                            Action("clip","Copy '{}'".format(private), lambda: setClipboardText(text)),
                            Action("clip","Copy '{}'".format(subtext), lambda: setClipboardText(subtext)),
                            Action("url","Open Documentation",lambda: openUrl(url))
                            ]))

                #short delay before we ask the API
                for number in range(50):
                    sleep(0.01)
                    if not query.isValid:
                        return

                debug("API Overview Query for AS"+ str(asn))
                r = self.ripe_api("as-overview",'as'+str(asn))
                if r:
                    if r['messages']:
                        #re-assamble some information
                        for m in r['messages']:
                            query.add(StandardItem(
                                id = md_id,
                                iconUrls=self.icon_default,
                                text = m[0],
                                subtext = m[1],
                                actions = [Action("clip","Copy messsage", lambda: setClipboardText(m[1]))]
                            ))
                    #cancel further items or requests if response was not ok
                    if r['status_code'] != 200:
                        return

                    #append some stats we found
                    if 'data' in r:
                        #default copy actions
                        actions = [
                                # Action("clip","Copy: 'AS{resource} - {holder}'".format(**r['data']), lambda: setClipboardText("AS{resource} - {holder}".format(**r['data']))),
                                Action("clip","Copy: '{holder}'".format(**r['data']), lambda v=r['data']['holder']: setClipboardText(v))
                                ]
                        #assemble custom ASN URL
                        for name,url in self.config['asn_url'].items():
                            actions.append(Action("url","Open {}".format(name),lambda u=url.format(r['data']['resource']): openUrl(u)))

                        #add the AS item
                        query.add(StandardItem(
                            id = "as",
                            text = "AS{resource} - {holder}".format(**r['data']),
                            subtext = "is announced" if r['data']['announced'] else "not announced",
                            iconUrls=self.icon_default,
                            actions = actions
                        ))

                        #ASN Block details if enabled
                        if 'block' in r['data'] and self.config['show_rir_blocks']:
                            query.add(StandardItem(
                            id = "block",
                            text = "AS Block {resource} - {desc}".format(**r['data']['block']),
                            subtext = r['data']['block']['name'],
                            iconUrls=self.icon_default,
                            actions = [
                                Action("clip","Copy "+r['data']['block']['resource'], lambda v=r['data']['block']['resource']: setClipboardText(v)),
                                Action("clip","Copy "+r['data']['block']['name'], lambda v=r['data']['block']['name']: setClipboardText(v)),
                                Action("clip","Copy "+r['data']['block']['desc'], lambda v=r['data']['block']['desc']: setClipboardText(v)),
                            ]
                            ))


                    #do a whois query
                    w = self.ripe_api("whois",query.string)

                    if w['messages']:
                        for m in r['messages']:
                            query.add(StandardItem(
                                id = md_id,
                                iconUrls=self.icon_default,
                                text = m[0],
                                subtext = m[1],
                                actions = [Action("clip","Copy messsage", lambda: setClipboardText(m[1]))]
                            ))
                        #cancel further items or requests if response was not ok
                        if r['status_code'] != 200:
                            return

                    if 'data' in w:
                        #loop over all whois results
                        for record in w['data']['records']:
                            #a whois-like object string is assembled with multiple strings below
                            whois_str=""
                            whois_substr=""
                            actions = []

                            #assign a icon on well known attributes
                            if record[0]['key'] in self.config['famous_objects']:
                                record_icon = [f"file:{Path(__file__).parent}/icon/"+record[0]['key'].lower()+".svg"]
                            else:
                                record_icon = [f"file:{Path(__file__).parent}/icon/whois.svg"]

                                #we always add a Copy option for first kv pair for (not nessesary for famous objects as they have famous attributes)
                                actions.append(
                                    Action("clip-first","Copy '{value}'".format(**record[0]), lambda v="{value}".format(**record[0]): setClipboardText(v))
                                )

                            for line in record:
                                #assamble whois object
                                whois_str += "{key:15} {value}\n".format(**line)

                                #look for interesting attributes for subtext and Copy action
                                if line['key'] in self.config['famous_attributes']:
                                    whois_substr += "{value} ".format(**line)

                                    #never add source as copy option, nobody need this
                                    if line['key'] == 'source': continue
                                    actions.append(Action("clip","Copy '{value}'".format(**line), lambda v=line['value']: setClipboardText(v)))
                            
                            # whois object is complete, add it as first copy option
                            actions.insert(0,Action("clip-object","Copy Whois Object", lambda: setClipboardText(whois_str)))

                            #add the record as a item
                            query.add((StandardItem(
                                id = record[0]['key'],
                                text =  "{key}: {value}".format(**record[0]),
                                subtext = whois_substr,
                                iconUrls= record_icon,
                                actions = actions )))
                else:
                    return query.add(StandardItem(
                        id = md_id,
                        text = "ASN not found",
                        subtext = w,
                        iconUrls=self.icon_default))

            # ====================
            # :: Prefix Search
            # ====================
            # prefix search is similar than ASN. Based on a overview and whois API query. Although the output is slightly different - a bit of redundant code here... :/
            elif prefix := self.is_prefix_or_address(query.string):
                private=None
                ptr=False

                #in case of a Host address /32 or no CIDR
                if type(prefix)==IPv4Address or type(prefix)==IPv6Address:

                    #check if the ip is part of a custom prefix, we need to know the key of the custom_prefix list
                    custom_index = [x for x in self.config['custom_prefix'].keys() if prefix in ip_network(x,strict=False)]

                    #check PTR if enabled but don't care much, just pass any exception.
                    if self.config['show_ptr']:
                        try:
                            if ptr := str(resolver.query(prefix.reverse_pointer,"PTR")[0]):
                                #prepare a ptr item, it will be added later. 
                                ptr = StandardItem(
                                    id = "ptr",
                                    iconUrls=[f"file:{Path(__file__).parent}/icon/ptr.svg"],
                                    text =  ptr,
                                    subtext = prefix.reverse_pointer,
                                    actions = [
                                        Action("clip","Copy '{}'".format(ptr), lambda v=ptr: setClipboardText(v)),
                                        Action("clip","Copy '{}'".format(prefix.reverse_pointer), lambda v=prefix.reverse_pointer: setClipboardText(v))
                                    ]
                                )    
                        except Exception:
                            pass
                else:
                    # in case of a Prefix (the comparision is slightly different)
                    custom_index = [x for x in self.config['custom_prefix'].keys() if prefix.subnet_of(ip_network(x,strict=False))]

                #check if the ip belongs to a private or custom_prefix list. 
                if custom_index:         
                    i = custom_index[0] #atm we care about the first hit
                    private = self.config['custom_prefix'][i]['name']
                    subtext = self.config['custom_prefix'][i]['info']
                    url = self.config['custom_prefix'][i]['url']          
                # next checks RFC ranges (hard coded backup if yaml is missing/overwritten)
                elif prefix.is_link_local:
                    private = "Link Local"  
                    subtext = "a link Local as RFC 4291"
                    url = "https://www.rfc-editor.org/rfc/rfc4291"
                elif prefix.is_loopback:
                    private = "Loopback"
                    subtext = "This is a Loopback RFC 2373 2.5.3"
                    url = "https://www.rfc-editor.org/rfc/rfc2373"
                elif prefix.is_private:
                    private = "Private"
                    subtext = "allocated for private networks iana-ipv4-special-registry or iana-ipv6-special-registry."
                    url = "https://www.rfc-editor.org/"
                elif prefix.is_multicast:
                    private = "Multicast"
                    subtext = "a multicast address see RFC 2373 2.7"
                    url = "https://www.rfc-editor.org/rfc/rfc2373"
                elif prefix.is_reserved:
                    private = "Reserved"
                    subtext = "one of the reserved IPv6 Network ranges"             
                elif prefix.is_unspecified:                    
                    private = "Unspecified"
                    subtext = "a unspecified address as defined in RFC 2373 2.5.2."
                    url = "https://www.rfc-editor.org/rfc/rfc2373"
                    
                # if the prefix is private return here and skip any API lookup
                if private:
                    query.add(StandardItem(
                            id = "private",
                            text = private,
                            subtext = subtext,
                            iconUrls=self.icon_default,
                            actions = [
                                Action("clip","Copy '{}'".format(private), lambda: setClipboardText(private)),
                                Action("clip","Copy '{}'".format(subtext), lambda: setClipboardText(subtext)),
                                Action("clip","Copy PTR '{}'".format(prefix.reverse_pointer), lambda: setClipboardText(prefix.reverse_pointer)),
                                Action("url","Open Documentation",lambda: openUrl(url))
                                ]))
                    if ptr: query.add(ptr)
                    return

                #short delay before we ask the API
                for number in range(50):
                    sleep(0.01)
                    if not query.isValid:
                        return
                    
                debug("Checking API for IP: "+ str(prefix))
                r = self.ripe_api("prefix-overview",str(prefix))
                if r:
                    #add some informative Message - if any
                    if r['messages']:
                        query.add(StandardItem(
                            id = "info",
                            iconUrls=self.icon_default,
                            text = r['messages'][0][0],
                            subtext = r['messages'][0][1]
                        ))
                    #cancel further items or requests if response was not ok
                    if r['status_code'] != 200:
                        return
                    
                    # Add some related Prefixes
                    if r['see_also']:
                        for see_also in r['see_also']:
                            actions = [Action("clip","Copy {}".format(see_also['resource']), lambda: setClipboardText(see_also['resource']))]
                            #assemble any custom URL
                            for name,url in self.config['prefix_url'].items():
                                actions.append(Action("url","Open {}".format(name),lambda u=url.format(r['data']['resource']): openUrl(u)))

                            query.add(StandardItem(
                                id = "seealso",
                                iconUrls=self.icon_default,
                                text = see_also['resource'],
                                subtext = "Related as "+ see_also['relation'],
                                actions = actions
                            ))

                    #lets prepare the main prefix item now...
                    #copy option is first and default
                    actions = [Action("clip","Copy {}".format(r['data']['resource']), lambda v=r['data']['resource']: setClipboardText(v))]

                    #assemble custom URL
                    for name,url in self.config['prefix_url'].items():
                        actions.append(Action("url","Open {}".format(name),lambda u=url.format(r['data']['resource']): openUrl(u)))
                    
                    #add the prefix item
                    query.add(StandardItem(
                        id = "origin",
                        text = r['data']['resource'],
                        subtext = "is announced" if r['data']['announced'] else "not announced",
                        iconUrls=self.icon_default,
                        actions = actions
                    ))

                    #add the PTR item if any
                    if ptr: query.add(ptr)

                    #any block details if enabled
                    if 'block' in r['data'] and self.config['show_rir_blocks']:
                        query.add(StandardItem(
                        id = "block",
                        text = "IP Block {resource} - {desc}".format(**r['data']['block']),
                        subtext = r['data']['block']['name'],
                        iconUrls=self.icon_default,
                        actions = [
                            Action("clip","Copy "+r['data']['block']['resource'], lambda v=r['data']['block']['resource']: setClipboardText(v)),
                            Action("clip","Copy "+r['data']['block']['name'], lambda v=r['data']['block']['name']: setClipboardText(v)),
                            Action("clip","Copy "+r['data']['block']['desc'], lambda v=r['data']['block']['desc']: setClipboardText(v)),
                            ]
                        ))

                    #add related ASN's
                    for asn in r['data']['asns']:
                        #default copy actions
                        actions = [
                                Action("clip","Copy AS{asn}".format(**asn), lambda v="AS"+str(asn['asn']): setClipboardText(v)),
                                Action("clip","Copy {holder}".format(**asn), lambda v=asn['holder']: setClipboardText(v))
                                ]
                        #assemble custom ASN URL
                        for name,url in self.config['asn_url'].items():
                            actions.append(Action("url","Open {}".format(name),lambda u=url.format(asn['asn']): openUrl(u)))

                        query.add(StandardItem(
                            id = "auth",
                            text = "AS{asn}: {holder}".format(**asn),
                            subtext = "announced by ^",
                            iconUrls=self.icon_default,
                            actions = actions
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
                                        if record[0]['key'] in self.config['famous_objects']:
                                            record_icon = [f"file:{Path(__file__).parent}/icon/"+record[0]['key']+".svg"]
                                        else:
                                            record_icon = [f"file:{Path(__file__).parent}/icon/whois.svg"]

                                        for line in record:
                                            #setup a whois like string
                                            whois_str += "{key:15} {value}\n".format(**line)

                                            if line['key'] in self.config['famous_attributes']:

                                                if line['key'] == 'origin':
                                                    #special kind for origin (route and route6) objects
                                                    whois_substr += "Origin AS{value} ".format(**line)
                                                    actions.append(Action("copy","Copy '{value}'".format(**line),lambda v=line['value']: setClipboardText(v)))
                                                    value = "AS{value}".format(**line)
                                                    actions.append(Action("copy","Copy 'AS{value}'".format(**line),lambda v=value: setClipboardText(v)))
                                                else:
                                                    whois_substr += "{value} ".format(**line)
                                                    #never add source as copy option
                                                    if line['key'] == 'source': continue
                                                    actions.append(Action("copy","Copy '{value}'".format(**line),lambda v=line['value']: setClipboardText(v)))

                                            if line['details_link']:
                                                if "stat.ripe.net" in line['details_link']:
                                                    actions.append(Action("url","Open RIPE Stat",lambda u=line['details_link']: openUrl(u)))
                                                elif "rest.db.ripe.net" in line['details_link']:
                                                    pass
                                                    #ignore any further api reference
                                                else:
                                                    actions.append(Action("url","Open URL",lambda u=line['details_link']: openUrl(u)))

                                        actions.insert(0,Action("clip-object","Copy '{key}' Whois Object".format(**record[0]), lambda v=whois_str: setClipboardText(v)))

                                        query.add(StandardItem(
                                        id = record[0]['key'],
                                        text =  "{key}: {value}".format(**record[0]),
                                        subtext = whois_substr,
                                        iconUrls=record_icon,
                                        actions = actions))

            else:

                r = self.ripe_api("searchcomplete",query.string)

                if r:
                    debug("General Search: "+ str(query.string))
                    for record in r['data']['categories']:
                        for item in record['suggestions']:
                            actions = []
                            if 'link' in item:
                                actions.append(Action("url","Open URL",lambda: openUrl(f"https://www.ripe.net/{item['link']}")))
                            actions.append(Action("clip","Copy '{value}' whois Object".format(**item), lambda: setClipboardText(item['value'])))

                            query.add(StandardItem(
                            id = md_id,
                            text =  item['value'],
                            subtext = item['description'],
                            # completion = md_id+ " "+ item['value'],
                            iconUrls=self.icon_default,
                            actions = actions))

