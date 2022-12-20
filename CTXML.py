from lxml import etree as ET
from time import time

def make_attrib(name,unique_id,icon=0):
    attribs = {
        "name":str(name),
        "unique_id":str(unique_id), #Don't forget to increment after
        "prog_lang":"custom-colors",
        "tags":"",
        "readonly":"0",
        "nosearch_me":"0",
        "nosearch_ch":"0",
        "custom_icon_id":str(icon), #Change for open/closed ports?
        "is_bold":"0",
        "foreground":"",
        "ts_creation":str(int(time())),
        "ts_lastsave":str(int(time()))
    }
    return attribs

def make_host(name,unique_id,ports,icon=0):
    hostattribs = make_attrib(name,unique_id)
    unique_id += 1

    host = ET.Element("node",attrib=hostattribs)

    for port in host.get_ports():
        is_open  = host.get_service(port[0],protocol=port[1]).open
        portnum  = port[0]
        protocol = port[1]
        service  = host.get_service(port[0],protocol=port[1]).service
        banner   = host.get_service(port[0],protocol=port[1]).banner
        
        #TODO: CHECK FOR CONFLICTS!
        portAttrib = make_attrib("{}/{} - {}".format(portnum,protocol,service),unique_id) #Open or closed?
        unique_id += 1
        tempPort = ET.SubElement(host,"node",attrib=portAttrib)
        if banner:
            tempBanner = ET.SubElement(tempPort,"rich_text")
            tempBanner.text = banner

    #boop = ET.SubElement(test,"node",attrib=attribstwo)
    #text = ET.SubElement(test,"rich_text")
    #text.text = "This is another demo value!"

    #parent.append(test)
    return host, unique_id
