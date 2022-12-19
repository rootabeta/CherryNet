# CherryNet
A utility for provisioning a cherrytree file with nmap scans

This utility is designed to automatically import nmap scan data into existing cherrytree files, using the outputs nmap can natively generate. 

See also: https://github.com/sergiodmn/cherrymap
Note that like CherryMap, this utility **WILL NOT WORK** with non-XML CherryTree files (although unlike CherryMap, CherryNet accepts both encrypted and unencrypted XML formats.) SQLite handling is **not** planned.  

# Featurelist
- [X] Process encrypted and unencrypted files, as pentests generally demand certain encryption-at-rest policies (Note in either case, XML formatting is required)
- [ ] Allow for custom formatting of added nodes for personalized layouts
- [ ] Declare parent nodes for new nodes to be added to - useful for large pentests with multiple network segments
- [ ] Enhanced at-a-glance provisioning and templating
- [ ] Adding, rather than replacing or duplicating, results for multiple scans for the same host (Similar to how pentest.ws and other services allow multiple scans of the same host)

# Usage
Usage information will be placed here once the tool is in a more complete state. 
Note that nmap scan importing relies on both .nmap and .xml files in the scans directory. These are then processed according to IP, then provisioned to the appropriate nodes. Like with CherryMap, we recommend using -oA in a dedicated nmap/ directory to generate scan files for easy catagorization and importing. 
