# xay dung ung dung luu tru file
from flask import *
import mysql.connector
import hashlib
import os
import random
import string

app = Flask(__name__)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404
import urlmap
app.run(host = '127.0.0.1', port = '5000')




# lam 1 cai download filezilla tu nginx
