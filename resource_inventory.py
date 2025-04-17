# -*- coding: utf-8 -*-
"""
Created on Thu Apr  3 14:24:39 2025

@author: ELarkin
"""

import requests
import pandas as pd
from dotenv import dotenv_values
import logging

#return environmental variables
env_val = dotenv_values('.env')

#format logging and location
logging.basicConfig(force=True, format='%(asctime)s : %(levelname)s : %(name)s : %(message)s', datefmt='%Y-%m-%d %H:%M:%S',
                    encoding='utf-8', level=logging.INFO, 
                    handlers=[logging.FileHandler(env_val.get('LOG_FILE')),logging.StreamHandler()])
#logging instance
logger = logging.getLogger('resource_inventory')

def inventory ():
    
    logger.info('inventory has started')
    
    #get dates
    end_time = pd.Timestamp.now()
    start_time = end_time - pd.Timedelta(days=7)

    end_date = end_time.strftime('%Y-%m-%d')
    start_date = start_time.strftime('%Y-%m-%d')

    #file name to save csv response
    filename = f'{end_date}_resource_inventory.csv'

    #Request authentication certificate
    url = "https://frontdoor.apptio.com/service/apikeylogin"

    params = {"Content-Type":"application/json","Accept":"application/json"}

    payload = {
        "keyAccess": env_val.get('PUBLIC_KEY'),
        "keySecret": env_val.get('PRIVATE_KEY')
        }
    headers = {
        "Content-Type": "application/json",
        }

    response = requests.request("POST", url, json=payload, headers=headers, params=params)
    
    logger.info(f'Authentication token has been requested, received {response}')
    
    auth_token = response.headers['apptio-opentoken']

    #request resource inventory
    url = "https://api.cloudability.com/v3/reporting/resourceinventory/run"

    querystring = {"":"","service":"ec2","vendor":"aws","startDate": start_date,"endDate": end_date}

    payload = ""
    headers = {
        "Accept": "text/csv",
        "apptio-environmentid": env_val.get('APPTIO_ENV'),
        "apptio-opentoken": auth_token
        }

    response = requests.request("GET", url, data=payload, headers=headers, params=querystring)
    
    logger.info(f'Resource Inventory request sent with {querystring}')
    logger.info(f'Resource Inventory request returned{response}')
    

    #write response to csv file
    with open(filename, "w") as file:
        file.write(response.text)
        
    file.close()
    
    logger.info(f'resource inventory has been saved to {filename}')
        
    return filename