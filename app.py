# Basic Libraries
from flask import Flask, render_template, request
import pandas as pd

# Libraries used by Google Drive API
import pickle
import os
import re
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import requests
from tqdm import tqdm
from tabulate import tabulate

# If modifying these scopes, delete the file token.pickle.
SCOPES = [
          'https://www.googleapis.com/auth/drive.metadata',
          'https://www.googleapis.com/auth/drive',
          'https://www.googleapis.com/auth/drive.file'
         ]

# Initialize the application
app = Flask(__name__)

# Functions

# Authenticates and accesses Google Drive 
def get_gdrive_service():
    creds = None
    # The file token.pickle stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port = 0)
        # Save the credentials for the next run
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    # Return Google Drive API service
    return build('drive', 'v3', credentials = creds)

# Get the formatted size of a file
def get_size_format(b, factor = 1024, suffix="B"):
    """
    Scale bytes to its proper byte format
    e.g:
        1253656 => '1.20MB'
        1253656678 => '1.17GB'
    """
    for unit in ["", "K", "M", "G", "T", "P", "E", "Z"]:
        if b < factor:
            return f"{b:.2f}{unit}{suffix}"
        b /= factor
    return f"{b:.2f}Y{suffix}"

# Given items returned by Google Drive API, print them in a tabular way
def list_files(items):
    if not items:
        # Empty drive
        print('No files found.')
    else:
        rows = []
        for item in items:
            # Get the File ID
            id = item["id"]
            # Get the name of file
            name = item["name"]
            try:
                # Parent directory ID
                parents = item["parents"]
            except:
                # Has no parrents
                parents = "N/A"
            try:
                # Get the size in nice bytes format (KB, MB, etc.)
                size = get_size_format(int(item["size"]))
            except:
                # Not a file, may be a folder
                size = "N/A"
            # Get the Google Drive type of file
            mime_type = item["mimeType"]
            # Get last modified date time
            modified_time = item["modifiedTime"]
            # Append everything to the list
            rows.append((id, name, parents, size, mime_type, modified_time))
        print("Files:")
        # Convert to a human readable table
        table = tabulate(rows, headers = ["ID", "Name", "Parents", "Size", "Type", "Modified Time"])
        # Print the table
        print(table)
        return rows

# Search for a file
def search(service, query):
    result = []
    page_token = None
    while True:
        response = service.files().list(q=query,
                                        spaces = "drive",
                                        fields = "nextPageToken, files(id, name, mimeType)",
                                        pageToken=page_token).execute()
        # Iterate over filtered files
        for file in response.get("files", []):
            result.append((file["id"], file["name"], file["mimeType"]))
        page_token = response.get('nextPageToken', None)
        if not page_token:
            # No more files
            break
    return result

# Empty the trash folder
def emptyTrash():
    service = get_gdrive_service()
    service.files().emptyTrash().execute()

# Download files from Google Drive
def download():
    service = get_gdrive_service()
    # Get all the files in the "Data" folder
    # Empty the trash folder else it would return the deleted files
    emptyTrash()
    # Retrieve all files
    results = service.files().list(
        pageSize = 5, fields="nextPageToken, files(id, name, mimeType, size, parents, modifiedTime)").execute()
    items = results.get('files', [])
    itemNames = list_files(items)
    # Get all items in folder
    requiredFiles = []
    folderId = "1KdVZUKTdpyv_6Q35Rlm4yIaLyJcxIgH6"
    for file in itemNames:
        if file[2][0] == folderId:
            requiredFiles.append(file[1])
    for fileName in requiredFiles:
        # Search for the file by name
        search_result = search(service, query = f"name = '{fileName}'")
        print(search_result)
        # Get the GDrive ID of the file
        file_id = search_result[0][0]
        # Make it shareable
        service.permissions().create(body = {"role": "reader", "type": "anyone"}, fileId = file_id).execute()
        # Download file
        download_file_from_google_drive(file_id, fileName)
    return requiredFiles

# Download file from Google Drive
def download_file_from_google_drive(id, destination):
    def get_confirm_token(response):
        for key, value in response.cookies.items():
            if key.startswith('download_warning'):
                return value
        return None

    def save_response_content(response, destination):
        CHUNK_SIZE = 32768
        # Get the file size from Content-length response header
        file_size = int(response.headers.get("Content-Length", 0))
        # Extract Content disposition from response headers
        content_disposition = response.headers.get("content-disposition")
        # Parse filename
        if content_disposition == None:
            return
        filename = re.findall("filename=\"(.+)\"", content_disposition)[0]
        print("[+] File size:", file_size)
        print("[+] File name:", filename)
        progress = tqdm(response.iter_content(CHUNK_SIZE), f"Downloading {filename}", total = file_size, unit = "Byte", unit_scale = True, unit_divisor = 1024)
        with open(destination, "wb") as f:
            for chunk in progress:
                if chunk: # Filter out keep-alive new chunks
                    f.write(chunk)
                    # Update the progress bar
                    progress.update(len(chunk))
        progress.close()

    # Base URL for download
    URL = "https://docs.google.com/uc?export=download"
    # Init a HTTP session
    session = requests.Session()
    # Make a request
    response = session.get(URL, params = {'id': id}, stream=True)
    print("[+] Downloading", response.url)
    # Get confirmation token
    token = get_confirm_token(response)
    if token:
        params = {'id': id, 'confirm':token}
        response = session.get(URL, params = params, stream=True)
    # Download to disk
    save_response_content(response, destination)  

# Getting files from Google Drive
def getData():
    emptyTrash()
    requiredFiles = download() # Download files to present

    # Import the data
    data = [] # Will store as fileName, Headers, Content
    for file in requiredFiles:
        # Read File
        currFile = [file]
        fileData = pd.read_csv(file)
        headings = fileData.columns
        requiredColumns = ["Name", "Average", "Standard Deviation"]
        currFile.append(requiredColumns)

        # Data Analysis
        results = pd.DataFrame(columns = requiredColumns)
        for col in headings:
            if col != "Date":
                average = fileData[col].mean()
                standardDeviation = fileData[col].std()
                results = results.append({
                    'Name': col,
                    'Average': round(average, 3),
                    'Standard Deviation': round(standardDeviation, 3)
                }, ignore_index = True)

        # Add data to file
        currFile.append(results.values)
        data.append(currFile)

    return data

@app.route('/', methods = ['POST', 'GET'])
def index():
    if request.method == "POST":
        pass
    else:
        try:
            return render_template('index.html', data = getData())
        except:
            return "Please refresh the page again!"

if __name__ == "__main__":
    app.run(debug = True)