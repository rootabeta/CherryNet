#!/usr/bin/python3
import argparse
import filecrypto
from libnmap.parser import NmapParser #NMAP
from lxml import etree as ET #XML
from time import time

def debug(string):
    if True: #Change to false later
        print("[DEBUG] {}".format(string))

if __name__ != "__main__":
    exit("Run this program directly")

parser = argparse.ArgumentParser(
        prog = "CherryNet",
        description = "A utility to import nmap files into CherryTree for pentesters",
        epilog = "This utility only accepts XML-formatted CherryTree files. If you are using .ctz (encrypted XML) format, you must supply the decryption password."
)

parser.add_argument('cherrytreefile',help="path to the cherrytree file")
parser.add_argument('nmapxml',help="path to the xml file to use")

parser.add_argument('-p','--password',help="password to use for ctz files")
parser.add_argument('-n','--new-file',help="create a new file (default - merge into existing). Ctd only.",action='store_true')
parser.add_argument('-c','--child-of',help="node to hang new entries off of. Default: top level. Existing files only.",default='cherrytree')
parser.add_argument('-f','--format',help="custom file to indicate how hosts should be structured. NOT IMPLEMENTED")

args = parser.parse_args()


def make_attrib(name,unique_id,icon=0): #CT has a lot of boilerplate we don't care much about
    attribs = {
        "name":str(name),
        "unique_id":str(unique_id), #Don't forget to increment after
        "prog_lang":"custom-colors", #Not sure about this one - if something breaks, this may be to blame
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

def processFile(targetFile, nmapFile, desiredRoot, isNewFile):
    foundParent = False

    if isNewFile:
        desiredRoot = "cherrytree"
        #TODO: Create blank template. Shouldn't be hard.
        raise NotImplementedError("This feature has not been implemented yet.")

    if not desiredRoot or desiredRoot == "cherrytree":
        desiredRoot = "cherrytree"
        foundParent = True

    # We are now ready to open the file!
    seen_IDs = [0] # In case of empty file
    tree = ET.parse(targetFile)
    root = tree.getroot()

    if root.tag != "cherrytree":
        print("Error: Archive is not a valid CherryTree save file. Ensure arguments are correct and that CherryTree is not running.")
        print("No changes have been made")
        return

    if desiredRoot == "cherrytree":
        parent = root
        foundParent = True

    for elem in root.iter(): #Not the most efficient code, but it works
        if elem.tag == "node":
            #pprint(elem.attrib)
            seen_IDs.append(int(elem.attrib["unique_id"])) #Add all known IDs
            if elem.attrib["name"] == desiredRoot and not foundParent: #Seek desired node, I believe in BFS style
                debug("FOUND PARENT")
                parent = elem #Not great, but it works
                foundParent = True

    if not foundParent or parent is None:
        print("Error: could not find desired parent")
        print("Check your spelling, or consider omitting the -c parameter")
        print("No changes have been made")
        return #Close out the file in case it's encrypted archive

    seen_IDs.sort()
    unique_id = seen_IDs[-1] + 1 # One up from the highest we've seen onward is free. This will be our starting point for new nodes.

    #for port in host.get_ports():
    #    print("|{}- {}/{} - {}".format('-' if host.get_service(port[0],protocol=port[1]).open else 'X', port[0],port[1],host.get_service(port[0],protocol=port[1]).service))
    #    if(host.get_service(port[0],protocol=port[1]).banner):
    #        print("|--- {}".format(host.get_service(port[0],protocol=port[1]).banner))

    nmapResults = NmapParser.parse_fromfile(nmapFile)
    for host in nmapResults.hosts: #TODO: YAML for host-by-host layout?
        seenThisHost = False #No duplicates... yet

        hostName = host.id #Name of node for host
        hostOS = host.os_fingerprint #Nice to have if we know it

        hostAttribs = make_attrib(hostName, unique_id)
        unique_id += 1

        for child in parent: #Check all children
            if child.tag == "node": #skip text
                if child.attrib:
                    if child.attrib["name"] and child.attrib["name"] == hostName:
                        debug("Duplicate - {}. Appending.".format(hostName))
                        seenThisHost = True
                        hostElement = child #Set parent of port data to the duplicate host
                        break

        if not seenThisHost:
            hostElement = ET.SubElement(parent,"node",attrib=hostAttribs) #TODO: Check here - is there already a node with our chosen title? If so, it's a duplicate scan!
            hostDetails = ET.SubElement(hostElement,"rich_text") #No need for attribs here
            hostDetails.text = "WRITEUP: \n1)"

        if hostOS: #Fill in details about the host itself - OS and such. Useful! All subsequent auto host notes go at the END. Set dupHost flag!
            hostDetails.text += "\n\n{}".format(hostOS) #TODO: Does this actually work?

        serviceElement = None
        if seenThisHost: 
            for child in hostElement: #Check all children
                if child.tag == "node": #skip text
                    if child.attrib:
                        if child.attrib["name"] and child.attrib["name"] == "Services":
                            serviceElement = child

        if serviceElement == None: #Fresh service element if none was recovered earlier
            serviceAttribs = make_attrib("Services",unique_id)
            unique_id += 1
            serviceElement = ET.SubElement(hostElement,"node",attrib=serviceAttribs)

        for port in host.get_ports(): 
            seenThisPort = False
            portElement = None
            is_open  = host.get_service(port[0],protocol=port[1]).open()
            state    = host.get_service(port[0],protocol=port[1]).state
            portnum  = port[0]
            protocol = port[1]
            service  = host.get_service(port[0],protocol=port[1]).service
            banner   = host.get_service(port[0],protocol=port[1]).banner
           
            quickID = "{}/{}".format(portnum,protocol)
            lenquickID = len(quickID)
            
            for child in hostElement:
                if child.tag == "node":
                    if child.attrib:
                        if child.attrib["name"] and child.attrib["name"].lower() == "services":
                            for grandchild in child:
                                if grandchild.tag == "node":
                                    if grandchild.attrib:
                                        if grandchild.attrib["name"] and grandchild.attrib["name"][:lenquickID] == quickID:
                                            seenThisPort = True
                                            debug("Duplicate port - {}:{}/{}".format(hostName,portnum,protocol))
                                            portElement = grandchild
                                            break


            portDetails = None
            if seenThisPort:
                for child in portElement:
                    if child.tag == "rich_text":
                        portDetails = child
                        break


            if portElement == None: #Never seen this host before - full makeover!
                portAttribs = make_attrib("{}/{} - {} ({})".format(portnum,protocol,service,state),unique_id) #TODO: Different icons for different port statuses? I know CT has them, but not their ID codes. Low priority.
                unique_id += 1 #NEVER FORGET THIS!

                portElement = ET.SubElement(serviceElement,"node",attrib=portAttribs)
                portDetails = ET.SubElement(portElement,"rich_text")

            if portDetails == None:
                portDetails = ET.SubElement(portElement,"rich_text")

            if banner:
                if portDetails.text:
                    portDetails.text += banner
                else:
                    portDetails.text = banner


        if not seenThisHost: #Never seen host - must be from scratch
            privescAttribs = make_attrib("Privesc/Local",unique_id)
            unique_id += 1
            privescElement = ET.SubElement(hostElement, "node", attrib=privescAttribs)

            lootAttribs = make_attrib("Loot",unique_id)
            unique_id += 1
            lootElement = ET.SubElement(hostElement, "node", attrib=lootAttribs)
            
            notesAttribs = make_attrib("Notes and Scratchpad",unique_id)
            unique_id += 1
            notesElement = ET.SubElement(hostElement, "node", attrib=notesAttribs) #Confession: I don't think I actually need the notesElement = part, but I'm too scared to delete it in case I do. This is my first time with lxml

#        debug("Attached {}!".format(hostName))


    ET.indent(root)

    with open(targetFile,"wb") as f:
        tree.write(f)
    print("Changes committed")

### MAIN
if args.format:
    raise NotImplementedError("CherryMap does not support custom host templates yet.")

if args.password: #Handle encrypted archives
    if 1==1: 
        archive = filecrypto.Archive(args.cherrytreefile) 
        targetFile = archive.open()
        processFile(targetFile, args.nmapxml, args.child_of, False) #New_file will be ignored
        archive.close()
    else: #New file
        raise NotImplementedError("CherryMap is not able to create a new file for encrypted volumes. Also, how did you get here? This is if 1==1 ... else. You are advised to apply for the Fields Medal, and to file a bug report.")
        archive = filecrypto.Archive(args.cherrytreefile) #TODO: New encrypted files? Need a way to tell filecrypto.Archive() not to look for a CTZ... maybe set a flag to None? 
        targetFile = archive.new() 
        processFile(targetFile, args.nmapxml, 'cherrytree', True) #Child_Of will be ignored
        archive.close()

else: #Plaintext
    if args.new_file: # New file
        #<?xml version="1.0" encoding="UTF-8"?>
        #<cherrytree>
        #  <bookmarks list=""/>
        #  <NODES HERE/>
        #</cherrytree>
        processFile(args.cherrytreefile,args.nmapxml,'cherrytree',True) #Child_Of will be ignored 
    else:
        processFile(args.cherrytreefile,args.nmapxml,args.child_of,False) 
