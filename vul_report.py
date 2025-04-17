# -*- coding: utf-8 -*-
"""
Created on Fri Apr 11 09:24:32 2025

@author: ELarkin
"""

from re import findall
from dotenv import dotenv_values
import pandas as pd
import numpy as np
import os
import logging

#return environmental variables
env_val = dotenv_values('.env')

#format logging and location
logging.basicConfig(force=True, format='%(asctime)s : %(levelname)s : %(name)s : %(message)s', datefmt='%Y-%m-%d %H:%M:%S',
                    encoding='utf-8', level=logging.INFO, 
                    handlers=[logging.FileHandler(env_val.get('LOG_FILE')),logging.StreamHandler()])

#Logging instance
logger = logging.getLogger('vul_report')


def join_data(vul_file, ri_dataframe):
    
    logger.info(f'join_data started for {vul_file}')
    
    #vulnerabilities to a dataframe
    vuls = pd.read_excel(vul_file)

    #filter for only csa or csr
    vuls = vuls[vuls['art'].isin(['csa', 'csr', 'csrun'])]
    vuls_len = len(vuls)
    
    logger.info(f'Vulnerability scan file opened with {vuls_len} CSA/CSR records')

    #parse ARNs into instances
    host2 = []

    for host in vuls['host']:
        if host.find('arn:aws:') == -1:
            host2.append(host)
        
        else:
            x = host.find('/') +1 
            host2.append(host[x:])

    #append host 2 to vulnerability dataframe
    vuls['host2'] = host2

    #join the resource inventory dataframe
    vuls = pd.merge(vuls, ri_dataframe, left_on='host2', right_on='Resource ID', how='left')

    #fill nan
    vuls = vuls.fillna(-1)

    
    #find the date from the vulnerability file name
    date = findall(r'\d{8}', vul_file)
    year = date[0][0:4]
    month = date[0][4:6]
    day = date[0][6:]
    
    date = f'{month}/{day}/{year}'

    #add revised host and date to dataframe
    revised_host = []
    dates = []

    for index, row in vuls.iterrows(): 
        if row['Instance Name'] == -1:
            revised_host.append(row['host'])
        else: revised_host.append(row['Instance Name'])
    
        dates.append(date)

    vuls.insert(0,'Revised Host', revised_host)
    vuls.insert(1,'Date',dates)

    #revise team names
    revised_teams = vuls['team'].str.capitalize()

    vuls.insert(1,'Revised Team', revised_teams)
 
    logger.info(f'join_data ended for {vul_file}')   
 
    return vuls


def run_report(directory, ri_file):
    
    logger.info(f'run_report has started with resource inventory file {ri_file}')
    
    #open resource inventory
    ri_new = pd.read_csv(ri_file)

    #only need the resource id and instance name
    ri_new = ri_new[['Resource ID', 'Instance Name']]

    #open historical ARNs file
    ri_hist_file = f'{directory}\\instance names.xlsx'
    ri_hist = pd.read_excel(ri_hist_file)

    #combine new and historical ARN data
    ri_new = pd.concat([ri_hist, ri_new])
    ri_new = ri_new.drop_duplicates()

    #open historical data
    history_file = f'{directory}\\Weekly Vulnerabilities.xlsx'
    history = pd.read_excel(history_file)
    his_len = len(history)
                                           
    logger.info(f'{history_file} has been opened with {his_len} rows')

    #add columns to history dataframe
    history['host2'] = np.nan
    history['Resource ID'] = np.nan
    history['Instance Name'] = np.nan

    #find vulnerability scan file
    scan_files = os.listdir(f'{directory}\\scan file')

    #loop through vulnerabilty scan files and join data
    for file in scan_files:
        vuls = join_data(f'{directory}\\scan file\\{file}', ri_new)
        history = pd.concat([history, vuls])
    
    #clean up annoying eol column
    eol = 'eol'
    if eol in history.columns:
        history.drop(columns=[eol], inplace=True)

    #get all resource id and resource names used
    ri_from_hist = history[history['Revised Host'] != history['host']]
    ri_from_hist = ri_from_hist.drop(ri_from_hist.columns[:-2], axis=1)
    ri_from_hist = ri_from_hist.dropna()

    #append to ri hist and save only unique records
    ri_hist = pd.concat([ri_hist, ri_from_hist])
    ri_hist = ri_hist.drop_duplicates()

    #save new instance name history file
    ri_hist.to_excel(ri_hist_file, index=False)
    logger.info(f'{ri_hist_file} has been updated')

    #drop unneeded columns
    history = history.drop(history.columns[-3:], axis=1)

    #save history file
    history.to_excel(history_file, sheet_name='Weeklys', index=False)
    his_len = len(history)
    logger.info(f'{history_file} has been saved with {his_len} rows')
    
    logger.info('run_report has ended')