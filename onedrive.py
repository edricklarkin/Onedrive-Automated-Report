# -*- coding: utf-8 -*-
"""
Created on Wed Apr 16 11:04:35 2025

@author: ELarkin
"""

from dotenv import dotenv_values
import requests
import json

env = dotenv_values('.env')

#Permissions being requested by the token
scopes = ['Files.ReadWrite.All']

#function to get a token either interactively or silently
def get_token(global_app):
    result = None
    
    #first check if there is an account in the cache
    #assumes there is only ever one account at a time
    accounts = global_app.get_accounts()

    if accounts:
        result = global_app.acquire_token_silent(scopes, accounts[0])
     
        #if there is not an account in the cache request one
    else: result = global_app.acquire_token_interactive(scopes)
        
    return result

#clean up having to write the same header ever time
def make_header(token):
    header = {
    "Accept": "application/json",
    "Authorization": f'Bearer {token}'
    }

    return header

#all urls wll start with this string
url = 'https://graph.microsoft.com/v1.0/me/drive/root:/Security/Vulnerability%20Reports'

#function to get files from onedrive and return to working drive
def get_file(source_file, target_file, token):
    
    #ensure source_file is url read
    source_file = source_file.replace(' ', '%20')
    
    header = make_header(token)
    
    response = requests.get(f'{url}/{source_file}:/content', headers=header)
    
    with open(target_file, "wb") as file:
        file.write(response.content)
    
    return response
    
#function to sends files from working drive to onedrive
def send_file(source_file, target_file, token):
    
    #ensure target file is url read
    target_file = source_file.replace(' ', '%20')
    
    header = make_header(token)
    
    file = open(source_file, 'rb')
    
    response = requests.put(f'{url}/{target_file}:/content', headers=header, data=file)
    
    return response

#check for file in scan file if available reuturn it's name
def check_for_scan_file(token):
    
    header = make_header(token)
    
    #Call graph API
    response = requests.get(f'{url}/scan%20file:/children', headers=header)
    
    #turn result a list of dicts that can be checked
    result = json.loads(response.text).get('value')
    
    return result
    
#delete file
def delete_file(target_file, token):
   
    #ensure target file is url read
    target_file = target_file.replace(' ', '%20')
   
    header = make_header(token)
   
    #Call graph API
    response = requests.delete(f'{url}/{target_file}', headers=header)
    
    return response
