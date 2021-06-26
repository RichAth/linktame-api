import json
import requests
from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from flask_cors import CORS

#Flask
app = Flask(__name__)
#CORS allows for localhost:3000 URL to access API through browser: see CORS
api = CORS(app)
#debugging enables printing to cmd
app_debug = 1
#URL endpoint to have creditLimit() function excicuted

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
