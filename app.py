from flask import Flask, render_template, request, redirect
import pandas as pd
import base64

# Initialize the application
app = Flask(__name__)

# Google Drive

# Convert to onedrive direct download link
def create_onedrive_directdownload (onedrive_link):
    data_bytes64 = base64.b64encode(bytes(onedrive_link, 'utf-8'))
    data_bytes64_String = data_bytes64.decode('utf-8').replace('/','_').replace('+','-').rstrip("=")
    resultUrl = f"https://api.onedrive.com/v1.0/shares/u!{data_bytes64_String}/root/content"
    return resultUrl

link = 'https://1drv.ms/u/s!AvbEtDUlZl2lb1f1QG4U5a4X_1E?e=mHKzS6'
directLink = create_onedrive_directdownload(link)

# Import the data
fileData = pd.read_csv(directLink)
headings = fileData.columns

# Data Analysis
results = pd.DataFrame(columns = ["Name", "Average", "Standard Deviation"])
for col in headings:
    if col != "Date":
        average = fileData[col].mean()
        standardDeviation = fileData[col].std()
        results = results.append({
            'Name': col,
            'Average': round(average, 3),
            'Standard Deviation': round(standardDeviation, 3)
        }, ignore_index = True)
headings = results.columns 
data = results.values

@app.route('/', methods = ['POST', 'GET'])
def index():
    if request.method == "POST":
        # task_content = request.form['content']
        # new_task = Todo(content = task_content)
        # try:
        #     db.session.add(new_task)
        #     db.session.commit()
        #     return redirect('/')
        # except:
        #     return "There was an issue adding the data!"
        pass
    else:
        return render_template('index.html', headings = headings, data = data)

# If there is a need for update and delete, please tweak this code

# @app.route('/delete/<int:id>')
# def delete(id):
#     task_to_delete = Todo.query.get_or_404(id)
#     try:
#         db.session.delete(task_to_delete)
#         db.session.commit()
#         return redirect('/')
#     except:
#         return "There was a problem deleting said task! "

# @app.route('/update/<int:id>', methods = ['GET', 'POST'])
# def update(id):
#     task = Todo.query.get_or_404(id)
#     if request.method == "POST":
#         task.content = request.form['content']
#         try:
#             db.session.commit()
#             return redirect('/')
#         except:
#             return 'There was an issue updating your task!'
#     else:
#         return render_template('update.html', task = task)

if __name__ == "__main__":
    app.run(debug = True)