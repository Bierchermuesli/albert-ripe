# RIPE Whois Lookup

This is a simple Albert Extension for network dudes. 

 - general IP/ASN Lookup (against RIPE Stats API)
 - lists more/less specific prefixes
 - lists related Whois objects and generates classic whois output
 - reverse DNS lookups
 - Private resources are checked locally to save API requests. 
 - Local overrides for custom Links, Prefixes or ASNs
 

## User Config
User Configuration gets simply appended to the default config and can look like this: 

 ~/.config/albert/RIPE-Whois.yaml
```
---
# This is my custom Config, URLs will be listed at the end
asn_url:
 AS-Stats: https://example.com/as-stats/history.php?as={}      

prefix_url:
 Routinator: http://rpki1.example.com:8080/ui/{}?validate-bgp=true

# my custom Prefixes, more specifics at the end please
custom_prefix:
    192.168.88.0/24:
      name: "FOOOOOO"
      info: "ah, yes my Home Network"
      url: "https://mywiki.local"
    10.0.1.0/24:
      name: "my HomeLab"
      info: "ah, yes my home lab"
      url: "https://mywiki.local"

# some custom ASNs to remember...
custom_as:
  65454:
      name: "my Lab"
      info: "our internal AS, you moron!"
      url: "http://wiki.example.com/AS"
```

## Install
```
git clone https://github.com/Bierchermuesli/albert-ripe.git  ~/.local/share/albert/python/plugins/ripe-whois
```