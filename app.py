# Basic Libraries
from webbrowser import get
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf.form import FlaskForm
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

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

# Athentication
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, EqualTo
from flask_bcrypt import Bcrypt
import json

# If modifying these scopes, delete the file token.pickle.
SCOPES = [
          'https://www.googleapis.com/auth/drive.metadata',
          'https://www.googleapis.com/auth/drive',
          'https://www.googleapis.com/auth/drive.file'
         ]

# Initialize the application
app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

# Config Key
app.config['SECRET_KEY'] = "Serenity070598"

# Login Stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
        # print("Files:")
        # # Convert to a human readable table
        # table = tabulate(rows, headers = ["ID", "Name", "Parents", "Size", "Type", "Modified Time"])
        # # Print the table
        # print(table)
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
def download(folderId):
    service = get_gdrive_service()
    # Get all the files in the "Data" folder
    # Empty the trash folder else it would return the deleted files
    emptyTrash()
    # Retrieve all files
    results = service.files().list(
        fields="nextPageToken, files(id, name, mimeType, size, parents, modifiedTime)").execute()
    items = results.get('files', [])
    itemNames = list_files(items)
    # Get all items in folder
    requiredFiles = []
    for file in itemNames:
        if file[2][0] == folderId:
            requiredFiles.append((file[1], file[0]))
    for fileName in requiredFiles:
        # Search for the file by name
        search_result = search(service, query = f"name = '{fileName[0]}'")
        print(search_result)
        # Get the GDrive ID of the file
        file_id = search_result[0][0]
        # Make it shareable
        service.permissions().create(body = {"role": "reader", "type": "anyone"}, fileId = file_id).execute()
        # Download file
        download_file_from_google_drive(file_id, fileName[0])
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

# Get Download Link
def getDownloadLink(id):
    # Base URL for download
    URL = "https://docs.google.com/uc?export=download"
    # Init a HTTP session
    session = requests.Session()
    # Make a request
    response = session.get(URL, params = {'id': id}, stream=True)
    return response

# Getting files from Google Drive
def getData():
    emptyTrash()
    requiredFiles = download("1KdVZUKTdpyv_6Q35Rlm4yIaLyJcxIgH6") # Download files to present

    # Import the data
    data = [] # Will store as fileName, Headers, Content
    for file in requiredFiles:
        # Read File
        currFile = [file[0]]
        fileData = pd.read_csv(file[0])
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
        currFile.append(getDownloadLink(file[1]).url)
        data.append(currFile)

    return data

def downloadOne(folderId):
    service = get_gdrive_service()
    # Get all the files in the "Data" folder
    # Empty the trash folder else it would return the deleted files
    emptyTrash()
    # Retrieve all files
    results = service.files().list(
        fields="nextPageToken, files(id, name, mimeType, size, parents, modifiedTime)").execute()
    items = results.get('files', [])
    itemNames = list_files(items)
    # Get all items in folder
    requiredFiles = []
    for file in itemNames:
        if file[2][0] == folderId:
            requiredFiles.append((file[1], file[0]))
    print(requiredFiles)
    requiredFiles.sort(reverse = True)
    requiredFiles = [requiredFiles[0]]
    for fileName in requiredFiles:
        # Search for the file by name
        search_result = search(service, query = f"name = '{fileName[0]}'")
        print(search_result)
        # Get the GDrive ID of the file
        file_id = search_result[0][0]
        # Make it shareable
        service.permissions().create(body = {"role": "reader", "type": "anyone"}, fileId = file_id).execute()
        # Download file
        download_file_from_google_drive(file_id, fileName[0])
    return requiredFiles

def getHTML(type):
    emptyTrash()
    APR_FolderId = "1uFNfMoGNl6fPCoCRXoRpXciKIQkZcNiE"
    TVL_FolderId = "1M7hg87R74-AJS7XaHbKvYEJRL3wy4oDe"

    if type == "APR":
        requiredFiles = downloadOne(APR_FolderId)
    elif type == "TVL":
        requiredFiles = downloadOne(TVL_FolderId)
    else:
        return "No such folder"

    # Import the data
    requiredFiles.sort(reverse = True)
    requiredFiles = requiredFiles[0]
    df = pd.read_csv(requiredFiles[0], header = [0, 1, 2])
    df = df.rename(columns = {'Unnamed: 0_level_1': 'Currency 1', 'Unnamed: 0_level_2': 'Currency 2'})
    return df    

def convertToPercentage(df, type):
    for col in df.columns:
        if col == ('Date', 'Currency 1', 'Currency 2'):
            pass
        else:
            if type == "APR":
                df[col] = df[col].apply(lambda x: str(int(np.floor(x * 100))) + "%")
            else:
                df[col] = df[col].apply(lambda x: str(int(np.floor(x))) + "%")
    return df

def getLinks(folderId):
    service = get_gdrive_service()
    # Get all the files in the "Data" folder
    # Empty the trash folder else it would return the deleted files
    emptyTrash()
    # Retrieve all files
    results = service.files().list(
        fields="nextPageToken, files(id, name, mimeType, size, parents, modifiedTime)").execute()
    items = results.get('files', [])
    itemNames = list_files(items)
    # Get all items in folder
    requiredFiles = []
    for file in itemNames:
        if file[2][0] == folderId:
            requiredFiles.append((file[1], getDownloadLink(file[0]).url))
    return requiredFiles

def getReports():
    emptyTrash()
    requiredFiles = getLinks("1B2Eqc0VJnsoS6T_69wKO7C2BOE9yP5QL") # Download files to present
    requiredFiles.sort(reverse = True)
    return requiredFiles

def getAPRGraphs():
    df = getHTML("APR")
    print(df)
    columns = df.columns
    graphPairs = []
    for i in range(1, len(columns)):
        pair = columns[i]
        title = str(pair[0]) + " - " + str(pair[1]) + " & " + str(pair[2])
        link = '../static/graphs/APR/' + title + '.png'
        fig, ax = plt.subplots(figsize = (8, 6))
        multipliedCol = df[columns[1]] * 100
        fig = plt.plot(df[columns[0]], multipliedCol)
        plt.grid()
        plt.axhline(y = 15, linewidth = 2, color = 'r')
        plt.axhline(y = 20, linewidth = 2, color = 'r')
        tickSpacing = 5
        ax.xaxis.set_major_locator(ticker.MultipleLocator(tickSpacing))
        plt.gca().xaxis.set_tick_params(rotation = 30)  
        plt.savefig("./static/graphs/APR/" + title + ".png")
        graphPairs.append((title, link))
    return graphPairs

def getTVLGraphs():
    df = getHTML("TVL")
    columns = df.columns
    graphPairs = []
    for i in range(1, len(columns)):
        pair = columns[i]
        title = str(pair[0]) + " - " + str(pair[1]) + " & " + str(pair[2])
        link = '../static/graphs/TVL/' + title + '.png'
        fig, ax = plt.subplots(figsize = (8, 6))
        fig = plt.plot(df[columns[0]], df[columns[1]])
        plt.grid()
        plt.axhline(y = 15, linewidth = 2, color = 'r')
        plt.axhline(y = 20, linewidth = 2, color = 'r')
        tickSpacing = 5
        ax.xaxis.set_major_locator(ticker.MultipleLocator(tickSpacing))
        plt.gca().xaxis.set_tick_params(rotation = 30)  
        plt.savefig("./static/graphs/TVL/" + title + ".png")
        graphPairs.append((title, link))
    return graphPairs

# Authentication System

# Run python and do db.create_all() to create the tables in an empty database

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(25), nullable = False, unique = True)
    password = db.Column(db.String(50), nullable = False)

class RegisterForm(FlaskForm):
    username = StringField(validators = [InputRequired(), Length(min = 5, max = 25)], render_kw = {"placeholder": "Username"})
    password = PasswordField(validators = [InputRequired(), Length(min = 7, max = 50)], render_kw = {"placeholder": "Password"})
    passwordRepeat = PasswordField(validators = [EqualTo('password'), InputRequired(), Length(min = 7, max = 50)], render_kw = {"placeholder": "Repeat Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username = username.data).first()
        if existing_user_username:
            raise ValidationError("Username already exists! Please choose a different one!")

class LoginForm(FlaskForm):
    username = StringField(validators = [InputRequired(), Length(min = 5, max = 25)], render_kw = {"placeholder": "Username"})
    password = PasswordField(validators = [InputRequired(), Length(min = 7, max = 50)], render_kw = {"placeholder": "Password"})
    submit = SubmitField("Login")

def flash_errors(form):
    """Flashes form errors"""
    for field, errors in form.errors.items():
        for error in errors:
            if error == "Field must be equal to password.":
                flash('Passwords did not match!', 'danger')
            else:
                flash(u"%s" % error, 'danger')
            break
        break

# Routes

@app.route('/home', methods = ['POST', 'GET'])
@login_required
def home():
    if request.method == "POST":
        pass
    else:
        try:
            # return render_template('index.html', data = getData())
            return render_template('index.html')
        except:
            return render_template('error.html')

@app.route('/', methods = ['POST', 'GET'])
@app.route('/login', methods = ['POST', 'GET'])
def login():
    form = LoginForm()
    if request.method == "POST":
        if form.validate_on_submit():
            user = User.query.filter_by(
                username = form.username.data
            ).first()
            if user:
                if bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user)
                    return redirect(url_for('home'))
                else:
                    flash(f'Wrong password!', category = 'danger')
            else:
                flash(f'Username does not exist!', category = 'danger')
        else:
            flash_errors(form)
    return render_template('login.html', form  = form)

@app.route('/logout', methods = ["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods = ['POST', 'GET'])
def register():
    form = RegisterForm()
    if request.method == "POST":
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data)
            new_user = User(
                username = form.username.data,
                password = hashed_password
            )
            db.session.add(new_user)
            db.session.commit()
            flash(f'Account successfully created! Please login now!',
                category='success')
            return redirect(url_for('login'))
        else:
            flash_errors(form)
    return render_template('register.html', form = form)

@app.route('/reports', methods = ['POST', 'GET'])
@login_required
def reports():
    try:
        return render_template('reports.html', data = getReports())
    except:
        return render_template('error.html')

@app.route('/TVL', methods = ['POST', 'GET'])
@login_required
def TVL():
    try:
        df = getHTML("TVL")
        df = convertToPercentage(df, "TVL")
        return render_template('TVL.html',  tables = [df.to_html(classes = "data", index = False)])
    except:
        return render_template('error.html')

@app.route('/APR', methods = ['POST', 'GET'])
@login_required
def APR():
    try:
        df = getHTML("APR")
        df = convertToPercentage(df, "APR")
        return render_template('APR.html',  tables = [df.to_html(classes = "data", index = False)])
    except:
        return render_template('error.html')

@app.route('/APR/Graphs', methods = ['POST', 'GET'])
@login_required
def APRGraphs():
    try:
        return render_template('APRGraph.html', graphs = getAPRGraphs())
    except:
        return render_template('error.html')

@app.route('/TVL/Graphs', methods = ['POST', 'GET'])
@login_required
def TVLGraphs():
    try:
        return render_template('TVLGraph.html', graphs = getTVLGraphs())
    except:
        return render_template('error.html')

if __name__ == "__main__":
    app.run(debug = True)