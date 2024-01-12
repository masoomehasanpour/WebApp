from init import create_app
from Model import Note
app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
    print(Note.data)
