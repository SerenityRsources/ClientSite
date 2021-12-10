from flask import Flask, render_template, request, redirect
import pandas as pd
from os import listdir
from os.path import isfile, join

# Initialize the application
app = Flask(__name__)

# Import the data
myPath = "G:/My Drive/Data"
onlyFiles = [f for f in listdir(myPath) if isfile(join(myPath, f))]
data = [] # Will store as fileName, Headers, Content
for file in onlyFiles:
    # Read File
    currFile = [file]
    fileData = pd.read_csv(myPath + '/' + file)
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
        return render_template('index.html', data = data)

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