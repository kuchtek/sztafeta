
from waitress import serve
from app import app
import os

if __name__ == "__main__":
    serve(app, host='0.0.0.0', 
          port=int(os.environ.get('PORT', 8888)), 
          threads=8, 
          url_prefix='/'
         )