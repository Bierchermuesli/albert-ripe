# -*- coding: utf-8 -*-
"""get details about prefixes, ASNs and runs WHOIS-like Queries from RIPE API

Synopsis: <trigger> ASN/Prefix
"""
from albert import *
import requests
import re
import shutil
import subprocess
import time
import yaml
from ipaddress import ip_network, ip_address, IPv4Address, IPv6Address
from dns import resolver
from pathlib import Path

LIVE_DEBOUNCE_SECONDS = 0.4
ASN_MAX = 4294967295  # 32-bit ASN upper bound (RFC 6793)

md_iid = "5.0"
md_version = "2.5"
md_name = "RIPE-Whois"
md_description = "whois like lookup with RIPE API"
md_license = "MIT"
md_url = "https://github.com/Bierchermuesli/albert-ripe"
md_maintainers = ["@Bierchermuesli"]
md_authors = ["@Bierchermuesli"]
md_lib_dependencies = ["requests", "pyyaml", "dnspython"]


class Plugin(PluginInstance, GeneratorQueryHandler):
    # --- private attributes
    _api_timeout = 1.5
    _show_rir_blocks = True
    _show_ptr = True

    def __init__(self):
        GeneratorQueryHandler.__init__(self)
        PluginInstance.__init__(self)
        
        self.icon_path = Path(__file__).parent / "icon.svg"
        self.as_regex = re.compile('^(?:as)?(?P<asn>\\d{1,10})$', re.IGNORECASE)
        
        self._init_configuration()

    # --- properties for settings
    @property
    def api_timeout(self):
        return self._api_timeout

    @api_timeout.setter
    def api_timeout(self, value):
        self._api_timeout = value
        self.writeConfig("api_timeout", value)

    @property
    def show_rir_blocks(self):
        return self._show_rir_blocks

    @show_rir_blocks.setter
    def show_rir_blocks(self, value):
        self._show_rir_blocks = value
        self.writeConfig("show_rir_blocks", value)

    @property
    def show_ptr(self):
        return self._show_ptr

    @show_ptr.setter
    def show_ptr(self, value):
        self._show_ptr = value
        self.writeConfig("show_ptr", value)
        
    def _init_configuration(self):
        """Load settings from config file or set defaults."""
        for key, type, default in [
            ("api_timeout", float, self._api_timeout),
            ("show_rir_blocks", bool, self._show_rir_blocks),
            ("show_ptr", bool, self._show_ptr),
        ]:
            conf = self.readConfig(key, type)
            if conf is None:
                self.writeConfig(key, default)
            else:
                setattr(self, f"_{key}", conf)
        
        # Legacy YAML config loading
        config_file = Path(__file__).parent.joinpath("config-defaults.yaml")
        default_config = self._load_yaml(config_file)
        config_file = self.configLocation().joinpath("config.yaml")
        user_config = self._load_yaml(config_file)
        for k, v in default_config.items():
            if k in user_config:
                if isinstance(user_config.get(k), dict) and isinstance(v, dict):
                    user_config[k].update(v)
            else:
                user_config[k] = v
        self.config = user_config

    def configWidget(self):
        return [
            {"type": "label", "text": __doc__},
            {
                "type": "doublespinbox",
                "label": "API Timeout (seconds)",
                "property": "api_timeout",
                "widget_properties": {"minimum": 0.5, "maximum": 10.0, "singleStep": 0.5}
            },
            {"type": "checkbox", "label": "Show RIR block details", "property": "show_rir_blocks"},
            {"type": "checkbox", "label": "Show PTR records for IP addresses", "property": "show_ptr"},
            {"type": "label", "text": f"For advanced configuration (custom URLs, etc.), copy <a href=\"{Path(__file__).parent.joinpath('config-defaults.yaml')}\">config-defaults.yaml</a> to <a href=\"{self.configLocation() / 'config.yaml'}\">{self.configLocation() / 'config.yaml'}</a> and adjust for your needs."},
        ]

    def defaultTrigger(self):
        return "w "

    def synopsis(self, query):
        return "ASN/Prefix"

    def _load_yaml(self, file: Path):
        if file.is_file():
            try:
                with open(file) as pointer:
                    return yaml.safe_load(pointer)
            except Exception as e:
                warning(f"Failed to load YAML file {file}: {e}")
        return {}

    def is_prefix_or_address(self, ip_str: str):
        try:
            return ip_address(ip_str)
        except ValueError:
            try:
                return ip_network(ip_str, strict=False)
            except ValueError:
                return None

    def ripe_api(self, uri: str, resource: str):
        headers = {'user-agent': f'Albert Launcher Plugin v{md_version}'}
        try:
            r = requests.get(f'https://stat.ripe.net/data/{uri}/data.json?resource={resource}', headers=headers, timeout=self.api_timeout)
            r.raise_for_status()
            return r.json()
        except requests.exceptions.RequestException as e:
            return {'messages': [['API Error', str(e)]], 'status_code': 500}

    def _get_icon(self, name: str = None):
        if name:
            icon = self.icon_path.parent / "icon" / f"{name}.svg"
            if icon.exists():
                return str(icon)
        return str(self.icon_path)

    def _add_to_copyq(self, text: str, label: str):
        if not shutil.which("copyq"):
            Notification(title="RIPE", text="copyq not installed; falling back to clipboard").send()
            setClipboardText(text)
            return
        note = f"ripe:{label}" if label else "ripe"
        try:
            subprocess.run(
                ["copyq", "write", "0",
                 "application/x-copyq-item-notes", note,
                 "text/plain", text],
                check=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            Notification(title="RIPE", text=f"Added to CopyQ history\n{text[:200]}").send()
        except Exception as e:
            warning(f"RIPE: copyq add failed: {e}")
            setClipboardText(text)

    def items(self, ctx):
        if not ctx.query:
            return

        search_term = ctx.query.strip()
        if not search_term:
            return

        # Debounce: each keystroke would otherwise fire a RIPE HTTP request
        # (and a PTR DNS lookup for IPs). Yield a placeholder, sleep, then
        # bail if the query has already moved on.
        yield [StandardItem(
            id="ripe-loading",
            text="Looking up...",
            subtext="stat.ripe.net",
            icon_factory=lambda: Icon.image(self._get_icon()),
        )]
        time.sleep(LIVE_DEBOUNCE_SECONDS)
        if not ctx.isValid:
            return

        results = []
        try:
            if asn_match := self.as_regex.match(search_term):
                asn = int(asn_match.group('asn'))
                if 1 <= asn <= ASN_MAX:
                    results = self._handle_asn_query(asn)
                else:
                    results = self._handle_general_search(search_term)
            elif prefix := self.is_prefix_or_address(search_term):
                results = self._handle_prefix_query(prefix)
            else:
                results = self._handle_general_search(search_term)
        except Exception as e:
            results.append(StandardItem(
                id="ripe-error",
                text="An unexpected error occurred",
                subtext=str(e),
                icon_factory=lambda: Icon.image(self._get_icon("error"))
            ))

        if ctx.isValid:
            yield results

    def _handle_asn_query(self, asn: int):
        items = []

        # --- Handle private/reserved ASNs ---
        private_info = None
        if asn in self.config.get('custom_as', {}):
            custom = self.config['custom_as'][asn]
            private_info = {
                'text': custom.get('name'),
                'subtext': custom.get('info', ''),
                'url': custom.get('url', ''),
            }
        elif asn == 23456:
            private_info = {'text': "AS_TRANS RFC6793", 'subtext': "2 to 4 byte ASN migrations", 'url': ''}
        elif asn in range(64496, 64512) or asn in range(65536, 65552):
            private_info = {'text': "RFC5398", 'subtext': "AS Number Reservation for Documentation Use", 'url': "https://www.rfc-editor.org/rfc/rfc5398"}
        elif asn in range(64512, 65535) or asn in range(4200000000, 4294967295):
            private_info = {'text': "RFC6996", 'subtext': "AS Number Reservation for Private Use", 'url': "https://www.rfc-editor.org/rfc/rfc6996"}
        elif asn in [65535, 4294967295]:
            private_info = {'text': "RFC7300", 'subtext': "Reservation of Last AS Numbers", 'url': "https://www.rfc-editor.org/rfc/rfc7300"}

        if private_info:
            actions = [Action("clip", f"Copy '{private_info['text']}'", lambda t=private_info['text']: setClipboardText(t))]
            if 'subtext' in private_info:
                actions.append(Action("clip_sub", f"Copy '{private_info['subtext']}'", lambda s=private_info['subtext']: setClipboardText(s)))
            if 'url' in private_info and private_info['url']:
                actions.append(Action("url", "Open Documentation", lambda u=private_info['url']: openUrl(u)))

            items.append(StandardItem(
                id="private_asn",
                text=private_info['text'],
                subtext=private_info.get('subtext', ''),
                icon_factory=lambda: Icon.image(self._get_icon()),
                actions=actions
            ))
            return items

        # --- Query RIPE API ---
        overview_data = self.ripe_api("as-overview", f"as{asn}")
        if overview_data.get('messages'):
            for i, m in enumerate(overview_data['messages']):
                items.append(StandardItem(id=f"asn_msg_{i}", text=m[0], subtext=m[1], icon_factory=lambda: Icon.image(self._get_icon("error"))))

        if overview_data.get('status_code') != 200:
            return items

        if 'data' in overview_data:
            data = overview_data['data']
            actions = [Action("clip_holder", f"Copy Holder: {data['holder']}", lambda v=data['holder']: setClipboardText(v))]
            for name, url in self.config.get('asn_url', {}).items():
                actions.append(Action("url", f"Open {name}", lambda u=url.format(data['resource']): openUrl(u)))
            
            items.append(StandardItem(
                id="as_overview",
                text=f"AS{data['resource']} - {data['holder']}",
                subtext="Announced" if data.get('announced') else "Not Announced",
                icon_factory=lambda: Icon.image(self._get_icon()),
                actions=actions
            ))

            if self.show_rir_blocks and 'block' in data:
                block = data['block']
                items.append(StandardItem(
                    id="rir_block",
                    text=f"AS Block {block['resource']} - {block['desc']}",
                    subtext=block['name'],
                    icon_factory=lambda: Icon.image(self._get_icon()),
                    actions=[
                        Action("clip_block_res", f"Copy {block['resource']}", lambda v=block['resource']: setClipboardText(v)),
                        Action("clip_block_name", f"Copy {block['name']}", lambda v=block['name']: setClipboardText(v)),
                    ]
                ))

        whois_data = self.ripe_api("whois", f"AS{asn}")
        if 'data' in whois_data:
            for record in whois_data['data'].get('records', []):
                if not record: continue
                
                whois_str = ""
                whois_substr = ""
                actions = []
                
                key = record[0].get('key', '')
                icon = self._get_icon(key.lower()) if key in self.config.get('famous_objects', []) else self._get_icon("whois")

                for line in record:
                    whois_str += f"{line.get('key', ''):15} {line.get('value', '')}\n"
                    if line.get('key') in self.config.get('famous_attributes', []):
                        whois_substr += f"{line.get('value', '')} "
                        if line.get('key') != 'source':
                            actions.append(Action(f"clip_{line.get('key')}", f"Copy {line.get('value')}", lambda v=line.get('value'): setClipboardText(v)))

                copyq_label = f"AS{asn} {record[0].get('key', '')}:{record[0].get('value', '')}"
                actions.insert(0, Action("clip_object", "Copy Whois Object", lambda w=whois_str: setClipboardText(w)))
                actions.insert(1, Action("copyq_object", "Add Whois to CopyQ history",
                                         lambda w=whois_str, l=copyq_label: self._add_to_copyq(w, l)))

                items.append(StandardItem(
                    id=key,
                    text=f"{record[0].get('key', '')}: {record[0].get('value', '')}",
                    subtext=whois_substr.strip(),
                    icon_factory=lambda i=icon: Icon.image(i),
                    actions=actions
                ))

        return items


    def _handle_prefix_query(self, prefix):
        items = []
        
        # --- Handle private/reserved prefixes ---
        private_info = None
        if isinstance(prefix, (IPv4Address, IPv6Address)):
            custom_index = [x for x in self.config.get('custom_prefix', {}) if prefix in ip_network(x, strict=False)]
        else:
            custom_index = [x for x in self.config.get('custom_prefix', {}) if prefix.subnet_of(ip_network(x, strict=False))]

        if custom_index:
            info = self.config['custom_prefix'][custom_index[0]]
            private_info = {'text': info.get('name'), 'subtext': info.get('info'), 'url': info.get('url')}
        elif prefix.is_link_local:
            private_info = {'text': "Link Local", 'subtext': "RFC 4291", 'url': "https://www.rfc-editor.org/rfc/rfc4291"}
        elif prefix.is_loopback:
            private_info = {'text': "Loopback", 'subtext': "RFC 2373 2.5.3", 'url': "https://www.rfc-editor.org/rfc/rfc2373"}
        elif prefix.is_private:
            private_info = {'text': "Private", 'subtext': "Private-Use", 'url': "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml"}
        elif prefix.is_multicast:
            private_info = {'text': "Multicast", 'subtext': "RFC 2373 2.7", 'url': "https://www.rfc-editor.org/rfc/rfc2373"}
        elif prefix.is_reserved:
            private_info = {'text': "Reserved", 'subtext': "Reserved IP range"}
        elif prefix.is_unspecified:
            private_info = {'text': "Unspecified", 'subtext': "RFC 2373 2.5.2", 'url': "https://www.rfc-editor.org/rfc/rfc2373"}

        if private_info:
            actions = [Action("clip", f"Copy '{private_info['text']}'", lambda t=private_info['text']: setClipboardText(t))]
            if private_info.get('subtext'):
                actions.append(Action("clip_sub", f"Copy '{private_info['subtext']}'", lambda s=private_info['subtext']: setClipboardText(s)))
            if private_info.get('url'):
                actions.append(Action("url", "Open Documentation", lambda u=private_info['url']: openUrl(u)))
            
            items.append(StandardItem(
                id="private_prefix", text=private_info['text'], subtext=private_info.get('subtext', ''),
                icon_factory=lambda: Icon.image(self._get_icon()), actions=actions
            ))
            return items

        # --- Query PTR Record ---
        if self.show_ptr and isinstance(prefix, (IPv4Address, IPv6Address)):
            try:
                answers = resolver.resolve(prefix.reverse_pointer, "PTR", lifetime=self.api_timeout)
                if ptr_record := str(answers[0]):
                    items.append(StandardItem(
                        id="ptr", text=ptr_record, subtext=prefix.reverse_pointer,
                        icon_factory=lambda: Icon.image(self._get_icon("ptr")),
                        actions=[
                            Action("clip_ptr", f"Copy {ptr_record}", lambda v=ptr_record: setClipboardText(v)),
                            Action("clip_rev", f"Copy {prefix.reverse_pointer}", lambda v=prefix.reverse_pointer: setClipboardText(v))
                        ]
                    ))
            except Exception as e:
                debug(f"PTR query failed for {prefix}: {e}")

        # --- Query RIPE API ---
        overview_data = self.ripe_api("prefix-overview", str(prefix))
        if overview_data.get('messages'):
            for i, m in enumerate(overview_data['messages']):
                items.append(StandardItem(id=f"prefix_msg_{i}", text=m[0], subtext=m[1], icon_factory=lambda: Icon.image(self._get_icon("error"))))
        
        if overview_data.get('status_code') != 200:
            return items

        if 'data' in overview_data:
            data = overview_data['data']
            actions = [Action("clip_res", f"Copy {data['resource']}", lambda v=data['resource']: setClipboardText(v))]
            for name, url in self.config.get('prefix_url', {}).items():
                actions.append(Action("url", f"Open {name}", lambda u=url.format(data['resource']): openUrl(u)))
            
            items.append(StandardItem(
                id="prefix_overview",
                text=data['resource'],
                subtext="Announced" if data.get('announced') else "Not Announced",
                icon_factory=lambda: Icon.image(self._get_icon()),
                actions=actions
            ))

            if self.show_rir_blocks and 'block' in data:
                block = data['block']
                items.append(StandardItem(
                    id="rir_block", text=f"IP Block {block['resource']} - {block['desc']}", subtext=block['name'],
                    icon_factory=lambda: Icon.image(self._get_icon()),
                    actions=[
                        Action("clip_block_res", f"Copy {block['resource']}", lambda v=block['resource']: setClipboardText(v)),
                        Action("clip_block_name", f"Copy {block['name']}", lambda v=block['name']: setClipboardText(v)),
                    ]
                ))

            for asn in data.get('asns', []):
                asn_actions = [
                    Action("clip_asn", f"Copy AS{asn['asn']}", lambda v=f"AS{asn['asn']}": setClipboardText(v)),
                    Action("clip_holder", f"Copy {asn['holder']}", lambda v=asn['holder']: setClipboardText(v))
                ]
                for name, url in self.config.get('asn_url', {}).items():
                    asn_actions.append(Action("url_asn", f"Open {name}", lambda u=url.format(asn['asn']): openUrl(u)))
                
                items.append(StandardItem(
                    id=f"auth_as_{asn['asn']}", text=f"AS{asn['asn']}: {asn['holder']}", subtext="Authoritative ASN",
                    icon_factory=lambda: Icon.image(self._get_icon()), actions=asn_actions
                ))

        whois_data = self.ripe_api("whois", str(prefix))
        if 'data' in whois_data:
            for record in whois_data['data'].get('records', []):
                if not record: continue
                
                whois_str, whois_substr, actions = "", "", []
                key = record[0].get('key', '')
                icon = self._get_icon(key.lower()) if key in self.config.get('famous_objects', []) else self._get_icon("whois")

                for line in record:
                    whois_str += f"{line.get('key', ''):15} {line.get('value', '')}\n"
                    if line.get('key') in self.config.get('famous_attributes', []):
                        whois_substr += f"{line.get('value', '')} "
                        if line.get('key') != 'source':
                            actions.append(Action(f"clip_{line.get('key')}", f"Copy {line.get('value')}", lambda v=line.get('value'): setClipboardText(v)))

                copyq_label = f"{prefix} {record[0].get('key', '')}:{record[0].get('value', '')}"
                actions.insert(0, Action("clip_object", "Copy Whois Object", lambda w=whois_str: setClipboardText(w)))
                actions.insert(1, Action("copyq_object", "Add Whois to CopyQ history",
                                         lambda w=whois_str, l=copyq_label: self._add_to_copyq(w, l)))

                items.append(StandardItem(
                    id=key, text=f"{record[0].get('key', '')}: {record[0].get('value', '')}", subtext=whois_substr.strip(),
                    icon_factory=lambda i=icon: Icon.image(i), actions=actions
                ))

        return items

    def _handle_general_search(self, search_term: str):
        items = []
        data = self.ripe_api("searchcomplete", search_term)
        if data.get('messages'):
            for i, m in enumerate(data['messages']):
                items.append(StandardItem(id=f"search_msg_{i}", text=m[0], subtext=m[1], icon_factory=lambda: Icon.image(self._get_icon("error"))))
            return items
        if 'data' in data:
            counter = 0
            for category in data['data'].get('categories', []):
                for suggestion in category.get('suggestions', []):
                    actions = []
                    if 'link' in suggestion:
                        actions.append(Action("url", "Open on ripe.net", lambda l=suggestion['link']: openUrl(f"https://www.ripe.net{l}")))
                    actions.append(Action("clip", f"Copy {suggestion['value']}", lambda v=suggestion['value']: setClipboardText(v)))
                    items.append(StandardItem(
                        id=f"search_{counter}",
                        text=suggestion.get('value'),
                        subtext=suggestion.get('description'),
                        icon_factory=lambda: Icon.image(self._get_icon()),
                        actions=actions
                    ))
                    counter += 1
        return items
