# CherryNet
A utility for provisioning a cherrytree file with nmap scans

This utility is designed to automatically import nmap data into cherrytree, using the outputs nmap can natively generate. 

The concept is similar to https://github.com/sergiodmn/cherrymap, but with some improvements planned

# Featurelist
- [X] Process encrypted and unencrypted files, as pentests generally demand certain encryption-at-rest policies (Note in either case, XML formatting is required)
- [ ] Allow for custom formatting of added nodes for personalized layouts
- [ ] Declare parent nodes for new nodes to be added to - useful for large pentests with multiple network segments
- [ ] Enhanced at-a-glance provisioning and templating
- [ ] Adding, rather than replacing or duplicating, results for multiple scans for the same host (Similar to how pentest.ws and other services allow multiple scans of the same host)
