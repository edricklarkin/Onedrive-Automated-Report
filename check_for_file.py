# -*- coding: utf-8 -*-
"""
Created on Fri Apr 11 09:28:42 2025

@author: ELarkin
"""

from vul_report import run_report
from resource_inventory import inventory
from dotenv import dotenv_values
import onedrive as od
import msal
import os
import logging
import time

#return environmental variables
env = dotenv_values('.env')

client_id = env.get('CLIENT_ID')
authority = env.get('AUTHORITY')
scopes = ['Files.ReadWrite.All']

#working directory file
directory =env.get('DIRECTORY')


# Optional logging
#logging.basicConfig(level=logging.DEBUG)  # Enable DEBUG log for entire script
#logging.getLogger("msal").setLevel(logging.INFO)  # Optionally disable MSAL DEBUG logs

# If for whatever reason you plan to recreate same ClientApplication periodically,
# you shall create one global token cache and reuse it by each ClientApplication
cache = msal.TokenCache()  # The TokenCache() is in-memory.
    # See more options in https://msal-python.readthedocs.io/en/latest/#tokencache

# Create a preferably long-lived app instance, to avoid the overhead of app creation
global_app = msal.PublicClientApplication(
    client_id,
    authority=authority,
    token_cache=cache
    )

#format logging and location
logging.basicConfig(force=True, format='%(asctime)s : %(levelname)s : %(name)s : %(message)s', datefmt='%Y-%m-%d %H:%M:%S',
                    encoding='utf-8', level=logging.INFO, 
                    handlers=[logging.FileHandler(env.get('LOG_FILE')),logging.StreamHandler()])

while True:

    #Logging instance
    logger = logging.getLogger('check_for_file')
    
    #get the token string for calling api
    token = od.get_token(global_app).get('access_token')
      
    #find vulnerability scan files if they exist
    scan_files = od.check_for_scan_file(token)
    
    num_of_files = len(scan_files)
    
    logger.info(f'There are {num_of_files} scan files available')
    
    #if there are files in the scan file folder run inventory and run report
    if num_of_files > 0:
        
        #download scan files to scan file folder
        for sf in scan_files:
            name = sf.get('name')
            od.get_file(f'/scan file/{name}', f'./scan file/{name}', token)
            
        #download instances names and weekly vulnerabilities
        od.get_file('Weekly Vulnerabilities.xlsx', 'Weekly Vulnerabilities.xlsx', token)
        od.get_file('instance names.xlsx', 'instance names.xlsx', token)
    
        #call resource inventory function, uncomment for production
        ri_file = inventory()
        
        #FOR TESTING without calling inventory function
        #ri_file = 'test_resource_inventory.csv'
        
        run_report(directory, ri_file)
        
        #save files to onedrive
        od.send_file('Weekly Vulnerabilities.xlsx', 'Weekly Vulnerabilities.xlsx', token)
        
        #delete files in the scan file folder
        for sf in scan_files:
            name = sf.get('name')
            os.remove(f'{directory}\\scan file\\{name}')
            od.delete_file(f'/scan file/{name}', token)
            
            logger.info(f'Scan file {name} has been deleted')
            
        #delete local files
        os.remove('Weekly Vulnerabilities.xlsx')
        
        #if resource inventory isn't the test file save to onedrive and delete local
        if ri_file != 'test_resource_inventory.csv':
            od.send_file(ri_file, f'resource inventories/{ri_file}', token)
            os.remove(f'{ri_file}')
    
    
    #save the updated logs to OneDrive
    od.send_file('vul_report.log', 'vul_report.log', token)
    
    #wait one hour before rechecking for a scan file
    time.sleep(3600)
        

    



