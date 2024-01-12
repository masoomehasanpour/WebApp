from flask import Blueprint, render_template, request, flash, jsonify
from flask_login import login_required, current_user
from init import db
from Model import Note
import json
show = Blueprint('show', __name__)


@show.route('/login')

def login():

        return render_template('login.html')



@show.route('/', methods=['GET', 'POST'])
@login_required

def home():
        if request.method == 'POST':
                note = request.form.get('note')

                if len(note) < 1:
                        flash('Note is too short!', category='error')
                else:
                        new_note = Note(data=note, user_id=current_user.id)
                        db.session.add(new_note)
                        db.session.commit()

        return render_template('index.html',user=current_user)
