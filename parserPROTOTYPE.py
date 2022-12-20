import sys
from lxml import etree as ET
from pprint import pprint
from time import time

print("Time is {}".format(int(time())))

seen_IDs = []

file = sys.argv[1]
foundParent = False
try:
    desiredroot = sys.argv[2]
except:
    desiredroot = 'cherrytree'

print("Hanging results from {}".format(desiredroot))
tree = ET.parse(file)
root = tree.getroot() #Cherrytree
if desiredroot == 'cherrytree':
    parent = root
    foundParent = True #That was easy

if root.tag != 'cherrytree':
    exit("Not a valid CT file!")

for elem in root.iter():
    print(elem.tag)
    if elem.tag == "node":
        print("NODE")
        pprint(elem.attrib)
        seen_IDs.append(int(elem.attrib["unique_id"]))
        if elem.attrib["name"] == desiredroot and not foundParent: 
            print("FOUND PARENT")
            foundParent = True
            parent = elem #Not great, but it works
        
    elif elem.tag == "rich_text":
        print("TEXT")
        print(elem.text)
    print()


seen_IDs.sort() #Sort seen IDs
highest_id = seen_IDs[-1]
avail_id = highest_id + 1
print("Seen IDs: {}".format(seen_IDs))
print("Next available ID: {}".format(avail_id)) #What ID to start from now

print(parent.tag,parent.attrib) # We know where to hang our entries!

#<node name="Learning Opportunities" unique_id="9" prog_lang="custom-colors" tags="" readonly="0" nosearch_me="0" nosearch_ch="0" custom_icon_id="0" is_bold="0" foreground="" ts_creation="1671479189" ts_lastsave="1671479218">
#  <rich_text>1) Check robots.txt on web!</rich_text>
#</node>

attribs = {
    "name":"DEBUG",
    "unique_id":str(avail_id), #Don't forget to increment after
    "prog_lang":"custom-colors",
    "tags":"",
    "readonly":"0",
    "nosearch_me":"0",
    "nosearch_ch":"0",
    "custom_icon_id":"0", #Change for open/closed ports?
    "is_bold":"0",
    "foreground":"",
    "ts_creation":str(int(time())),
    "ts_lastsave":str(int(time()))
}
avail_id += 1
        
test = ET.Element("node",attrib=attribs)
text = ET.SubElement(test,"rich_text")
text.text = "This is a demo value!"

parent.append(test)



print("\nFINAL CUT")
ET.indent(root)
print(ET.tostring(root,pretty_print=True).decode())

with open("OUTFILE.xml","wb") as f:
    tree.write(f)
#Each node has a <rich_text> with the text (e.g. for a service, the banner info) and a <node> for any subnodes (e.g. services>22 - ssh)

