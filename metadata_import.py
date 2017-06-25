#!/usr/bin/env python
import pymongo
import argparse
import hashlib
import sys
import os
import subprocess
from HTMLParser import HTMLParser

# Provide a helpful API to user
arg_parser = argparse.ArgumentParser("Consume metadata for a sample into the database")
arg_parser.add_argument("-f", "--filename", required=True, help="Filename to internalize")

args = arg_parser.parse_args()

# Try opening the file (in binary mode), and fail if we cannot
malware_file = open(args.filename, "rb")
if not malware_file:
  sys.stderr.write("There was an error reading the file\n")
  sys.exit(1)


# Establish a connection to the MongDB server
conn = pymongo.MongoClient()

# Retrieve a handle to the "cs7038" database
db = conn["cs7038"]

# Retrieve a handle to the "malware" collection
mwcoll = db["malware"]

# Empty dictionary representing the file data object
malware_object = {}

# We decided there are a group of values that we always want to consume:
# MD5, SHA-1, SHA-256, File name, File size, File type
#
md5_engine =  hashlib.md5()
sha1_engine = hashlib.sha1()
sha256_engine = hashlib.sha256()

malware_bytes = malware_file.read()
md5_engine.update(malware_bytes)
sha1_engine.update(malware_bytes)
sha256_engine.update(malware_bytes)

malware_object["md5"] = md5_engine.hexdigest()
malware_object["sha1"] = sha1_engine.hexdigest()
malware_object["sha256"] = sha256_engine.hexdigest()
malware_object["size"] = os.stat(args.filename).st_size

# Check to see if there's already an object in the DB matching this
# content:
cur = mwcoll.find({'size': malware_object["size"], "sha256": malware_object["sha256"]})

# If the results are a list of one, then retrieve the object id and then update the object
# to add the filename, if it is indeed a never-before-seen name of the file
if cur.count() == 1:
    db_obj = cur[0]
    obj_id = db_obj['_id']
    mwcoll.update({'_id': obj_id}, {'$addToSet': {'names': args.filename}})

    # then leave, because we can assume all the other data is already there from
    # content analysis
    sys.exit(0)

# Create new list with the filename provided
malware_object["names"] = [os.path.basename(args.filename)]

# Next, execute the "exiftool" program to identify file type and other data
exiftool_proc = subprocess.Popen(["exiftool", "-t", args.filename], stdout=subprocess.PIPE)

malware_object["type"] = ""
for result_line in exiftool_proc.stdout:
  # All entries, because of -t, are key\tvalue formatted
  # If these exist, also import them:
  # Company Name, Author, File Description, Creation or Modification time
  try:
  	data = result_line.decode('utf-8').strip().split('\t')
  except Exception:
	data = result_line.strip().split('\t')
  if data[0] == 'File Type':
    malware_object["type"] = data[1]
  elif data[0] == 'Time Stamp':
    malware_object["creation_time"] = data[1]
  elif data[0] == 'Create Date':
    malware_object["creation_time"] = data[1]
  elif data[0] == 'Modify Date':
    malware_object["modification_time"] = data[1]
  elif data[0] == 'Author':
    malware_object["author"] = data[1]
  elif data[0] == 'Company Name':
    malware_object["company"] = data[1]
  elif data[0] == 'File Description':
    malware_object["file description"] = data[1]

if malware_object["type"] == "PDF":
	malware_object['Encoding'] = []
	malware_object['Filter'] = []
	malware_object['javaScriptFunctions']= []
	malware_object['URI'] = []
if malware_object["type"] == "HTML":  
	malware_object["externalScriptLinks"] = []
	malware_object["externalCSSLinks"]=[]
	malware_object['javaScriptFunctions']= []
# Complete exectution, then close handle
exiftool_proc.wait()
exiftool_proc = None

# Also, we decided there are a few items that are conditional:

#Extract Encoding, Filter, JavaScript function, URI, Script from pdf and html
if malware_object["type"] == "PDF" or malware_object["type"] == "HTML" :
		parser_proc = subprocess.Popen(["strings",args.filename], stdout=subprocess.PIPE)
		for result_line in parser_proc.stdout:
        	   a = result_line.decode('utf-8').strip().strip("<<").split()
 		   if a:
        		if a[0] == "/Encoding":
			        r = a[1].strip("//")
                		malware_object['Encoding'].append(r)
			elif a[0] == "/Filter":
				r =  a[1].strip("//")
				malware_object['Filter'].append(r)
			elif a[0] == "function":
				r = a[1].strip("{")
				malware_object['javaScriptFunctions'].append(r)
			elif a[0] == "/URI":
				r =  a[1].strip("(").strip(")")
				malware_object['URI'].append(r)
			elif a[0] == "script" and a[1] == "type='text/javascript'":
				r = a[2].strip("src=").strip("'").strip("</script>")
				malware_object["externalScriptLinks"].append(r)
		parser_proc.wait()
		parser_proc = None

#Extract external CSS Links from html
class MyHTMLParser(HTMLParser):
    def handle_starttag(self,tag,attrs):
        if tag == "link":
	   for s in attrs:
	     if "text/css" in s:
		result = [s for s in attrs if "href" in s]
		if  result[0][1] != "":
			malware_object["externalCSSLinks"].append(result[0][1])



htmldata=MyHTMLParser()
try:
	htmldata.feed(malware_bytes)
	htmldata.close()
except Exception:
	pass

# Exit early if not a PE32 file
if malware_object["type"] != "Win32 EXE" and malware_object["type"] != "Win32 DLL":
    mwcoll.insert(malware_object)
    print("Added to database: " + repr(malware_object))
    sys.exit(0)

# If file type is a PE32 EXE or DLL, then: List of section names, compiled Time Stamp (as creation time)
objdump_proc = subprocess.Popen(["objdump", "-x", args.filename], stdout=subprocess.PIPE)

# Walk through results till we encounter the "Sections:" table
for result_line in objdump_proc.stdout:
    if result_line.decode('utf-8').find("Sections:") == 0:
      break

# Ignore heading
try:
	objdump_proc.stdout.readline()
except Exception:
	pass

malware_object['sections'] = []
malware_object['sections_size'] = []
malware_object['sections_LMA'] = []
# Process table
for result_line in objdump_proc.stdout:
    cleaned_line = result_line.decode('utf-8').strip()

    # The SYMBOL TABLE comes after the section table, and indicates end of section table
    if cleaned_line.find('SYMBOL TABLE') == 0:
        break


    # Ignore lines that don't begin with a number

    if len(cleaned_line) == 0 or ord(cleaned_line[0]) < ord('0') or ord(cleaned_line[0]) > ord('9'):
        continue
   # Extract sections names,size and virtual address
    fields = cleaned_line.split()
    malware_object['sections'].append(fields[1])
    malware_object['sections_size'].append(fields[2])
    malware_object['sections_LMA'].append(fields[3])

objdump_proc.wait()
objdump_proc = None



# Insert into database
mwcoll.insert(malware_object)
print("Added to database: " + repr(malware_object))
