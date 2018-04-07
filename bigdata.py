# -*- coding: utf-8 -*-
#!/usr/bin/python
#############################################################################################
# Big Data Vulnerability Scanning and Analysis for learning and or Bug Bunties.
# Whatever Your poison, this is My take on synk's Blog post of the js libraries vuln.
# I remember a good person once told me leveraging a tool is great but coding stuff to find its better.
# So with my free access to CPE and the 300 worth of free credits from google along with Big Query.
# I was able to put together this tool to utilize the data I created from their dataset and. 
# Do this testing that http archive abstracts using lighthouse using python and pandas to ingest the huge
# Request data.
#
#
##############################################################################################
import sys
import boto
import gcs_oauth2_boto_plugin
import os
import shutil
import StringIO
import tempfile
import time
import uuid
import subprocess
import gzip
from google.cloud import storage
import pandas as pd
import requests
import urllib2
from urlparse import urlparse
from threading import Thread
import httplib, sys
from Queue import Queue
import socket
sock = socket.socket()
sock.settimeout(3)
import uuid
# URI scheme for Cloud Storage.
GOOGLE_STORAGE = 'gs'
# URI scheme for accessing local files.
LOCAL_FILE = 'file'


CLIENT_ID = 'getyourclientidfromgooglecloudconsole'
CLIENT_SECRET = 'clientsecret'
project_name = "project_name"
gcs_oauth2_boto_plugin.SetFallbackClientIdAndSecret(CLIENT_ID, CLIENT_SECRET)



#delete report path & compressFileName per run  after uploaded to cloud
urls_to_test = []
audit_urls = []
concurrent = 400
q = Queue(concurrent * 2)




def list_buckets():
    buckets = []
    uri = boto.storage_uri('', GOOGLE_STORAGE)
    # If the default project is defined, call get_all_buckets() without arguments.
    for bucket in uri.get_all_buckets(headers=header_values):
        print(bucket.name)
        buckets.append(bucket.name)
    return buckets



def return_acl_entries(bucket_name):
    acl_entries_local = []
    bucket_uri = boto.storage_uri(bucket_name, GOOGLE_STORAGE)
    for entry in bucket_uri.get_bucket().get_acl().entries.entry_list:
        entry_id = entry.scope.id
        if not entry_id:
           entry_id = entry.scope.email_address
           entry_data_local = {'entry-id':entry_id,'Scope':entry_id,'Permission':entry.permission}
           print('SCOPE: %s' % entry_id)
           print('PERMISSION: %s\n' % entry.permission)
           acl_entries_local.append(entry_data_local)
           #list objects by bucket_name
    return acl_entries_local

           
def list_objects(bucket_name):
    buckets = []
    uri = boto.storage_uri(bucket_name, GOOGLE_STORAGE)
    for obj in uri.get_bucket():
        bucket_data = {'uri-scheme':uri.scheme,'uri_bucket-name':uri.bucket_name,'obj-name':obj.name,'obj-contents':obj.get_contents_as_string()}
        print('%s://%s/%s' % (uri.scheme, uri.bucket_name, obj.name))
        print('  "%s"' % obj.get_contents_as_string())
        buckets.append(bucket_data)
    return buckets


def modfile_acl(bucket_name,filename,email_address):
    #modify file access controls
    uri = boto.storage_uri(bucket_name + '/'+filename, GOOGLE_STORAGE)
    print(str(uri.get_acl()))
    uri.add_email_grant('FULL_CONTROL', email_address)
    print(str(uri.get_acl()))


    
def upload_blob(bucket_name, source_file_name, destination_blob_name):
 """Uploads a file to the bucket."""
 storage_client = storage.Client()
 bucket = storage_client.get_bucket(bucket_name)
 blob = bucket.blob(destination_blob_name)
 blob.upload_from_filename(source_file_name)
 print('File {} uploaded to {}.'.format(
 source_file_name,
 destination_blob_name))


    
#create bucket working stably
def create_bucket():
    import datetime
    now = time.time()
    bucket_name = 'lighthouse-%d' % now
    # Your project ID can be found at https://console.cloud.google.com/
    # If there is no domain for your project, then project_id = 'YOUR_PROJECT'
    project_id = project_name
    
    
    # Instantiate a BucketStorageUri object.
    if bucket_name:
        
        # Try to create the bucket.
        try:
           uri = boto.storage_uri(bucket_name, GOOGLE_STORAGE)
           # If the default project is defined,
           # you do not need the headers.
           # Just call: uri.create_bucket()
           header_values = {"x-goog-project-id": project_id}
           uri.create_bucket(headers=header_values)
           
        except:
             print('Failed to create bucket:')
             
    print('Successfully created bucket "%s"' % bucket_name)        
    return bucket_name



def command_wait(command):
    try:
       p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
       (output, err) = p.communicate()  

       #This makes the wait possible
       p_status = p.wait()

       #This will give you the output of the command being executed
       print("Command output: " + output)
       return output
    except:
        pass



#use pandas with dataframes to acess the data we need to iterate over with lighthouse
def gentle_panda(filename,amount):
    data = pd.read_csv(filename, nrows=int(amount))
    print(data.columns)
    df = pd.DataFrame(data)
    print(df)
    pandas_datas = []
    for row in df.itertuples(index=True, name='Pandas'):
        local_dict = {'url':getattr(row, "url"),'method':getattr(row, "method")}
        print(getattr(row, "url"), getattr(row, "method"))
        pandas_datas.append(local_dict)
    return pandas_datas


def urldecode(s):
    return urllib2.unquote(s).decode('utf8')

def check_urls(url_to_check):
    url = urldecode(url_to_check)
    resp = requests.head(url,verify=False,timeout=3,allow_redirects=True)
    
    if "200" in str(resp.status_code) or  "301" in str(resp.status_code):
       print(resp.status_code, resp.text, resp.headers)
       if url in audit_urls:
          pass
       else:
           audit_urls.append(url)

def lighthouse_commander(url,now):
    file_name = "reports/"+str(now)+"report.html"
    lighthouse_command = "lighthouse --chrome-flags=--headless --output-path="+file_name+""" """+url 
    output=command_wait(lighthouse_command)
    print(lighthouse_command)
    return file_name

def execute_report_command():
    #giving error after creating and trying to use but works if we create out of python first?
    create_report_dir = """sudo mkdir """+report_path
    output=command_wait(create_report_dir)
    print(create_report_dir) 
    return output


def delete_report_command(report_path):
    #giving error after creating and trying to use but works if we create out of python first?
    delete_report_dir = """rm  """+report_path
    output=command_wait(create_report_dir)
    print(create_report_dir) 
    return output

def doWork():
    while True:
        url = q.get()
        status, url = getStatus(url)
        doSomethingWithResult(status, url)
        q.task_done()

def getStatus(ourl):
    try:
        url = urlparse(ourl)
        conn = httplib.HTTPConnection(url.netloc, timeout=3)   
        conn.request("HEAD", url.path)
        res = conn.getresponse()
        return res.status, ourl
    except:
        return "error", ourl

def doSomethingWithResult(status, url):
    temp_url = urldecode(url)
    if "200" in str(status):
       print(status, temp_url)
       if url in audit_urls:
          pass
       else:
           audit_urls.append(url)
 
    else:
        print(status, temp_url)
        


def requests_large(url_list):
   #pass in a list and add it to the queue
   
   for i in range(concurrent):
       t = Thread(target=doWork)
       t.daemon = True
       t.start()
   try:
       for url in url_list:
           q.put(url.strip())
       q.join()
   except:
       pass





    
def main():
    filename = sys.argv[1]
    amount = sys.argv[2]
	
    return_data = gentle_panda(filename,amount)
    for datas in return_data:
        urls_to_test.append(datas["url"])
        
    
    
    requests_large(urls_to_test) 
   
    print(len(audit_urls))
   
    
    test_bucket = create_bucket()
    print("Succesfuly Created:"+test_bucket) 
    for urls in audit_urls:
        nowuuid = str(uuid.uuid4().get_hex().upper()[0:6])
        report_name = "reportnew"+nowuuid+".html"
        try:
           report_file = lighthouse_commander(urls,nowuuid)
           upload_blob(test_bucket, report_file,report_name)
           try:
              #delete_report_command(report_file)
			  #still working on this part :)
           except:
               pass
        except:
            pass
        
    
main()
