import unicodedata
from flask import Flask, request, redirect, jsonify, session, render_template, url_for
import requests
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import logging

#----------------------- APP CONFIG -----------------------
app = Flask(__name__)
app.logger.addHandler(logging.StreamHandler())
app.logger.setLevel(logging.INFO)
app.secret_key = "sekretny_klucz"
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

load_dotenv()
#--------------------- ENVIROMENT VARIABLES -----------------------
URI = os.environ.get('URI')
CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
REDIRECT_URI = f'{URI}/callback'  # Ustaw swoje URI przekierowania

STRAVA_CLIENT_ID = os.environ.get('STRAVA_CLIENT_ID')
STRAVA_CLIENT_SECRET = os.environ.get('STRAVA_CLIENT_SECRET')
STRAVA_REDIRECT_URI = f'{URI}/strava_callback' 

@app.context_processor
def inject_footer_data():
    return {
        'current_date': '2024',
        'app_version': '0.1'
    }
#--------------------- HEJTO ROUTES -----------------------
@app.route('/')
def login():
    # URL autoryzacyjny
    if 'access_token' in session.keys():
        if 'strava_access_token' in session.keys():
            return redirect(url_for('fetch_athlete_activities')) 
        else:
            redirect_url = url_for('callback', code=session['access_token'])
            return redirect(redirect_url)
    auth_url = (
        'http://auth.hejto.pl/authorize?'
        'response_type=code&'
        f'client_id={CLIENT_ID}&'
        f'redirect_uri={REDIRECT_URI}&'
        'scope=write:uploads write:posts read:account:profile'
    )
    return redirect(auth_url)

@app.route('/callback')
def authorize():
    authorization_code = request.args.get("code") or session.get("access_token")
    if not authorization_code:
        raise Exception("Authorization code not provided", 400)
    try:
        app.logger.info("Getting hejto token")
        token = get_hejto_token(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            authorization_code=authorization_code
        )
        app.logger.info("Got hejto token")
        session['access_token'] = token
        session.permantent = True
        app.logger.info("Got hejto token and saved to session")
        return render_template('authorize_strava.html')
    except Exception:
        auth_url = generate_authorization_url()
        return redirect(auth_url)

def generate_authorization_url():
    return (
        f'http://auth.hejto.pl/authorize?'
        'response_type=code&'
        f'client_id={CLIENT_ID}&'
        f'redirect_uri={REDIRECT_URI}&'
        'scope=write:uploads write:posts read:account:profile'
    )

def get_hejto_token(client_id, client_secret, authorization_code):
    url = 'https://auth.hejto.pl/token'
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT_URI,
        "code": authorization_code
    }
    headers = {
        "Content-Type": "application/json"
    }
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 200:
        token_data = response.json()
        return token_data.get('access_token')
    else:
        app.logger.error("Something goes wrong")
        raise Exception(f"Failed to retrieve token: {response.status_code} {response.text}")

def get_posts(access_token, community='Sztafeta', limit=1):
    url = f'https://api.hejto.pl/posts?community={community}&limit={limit}'
    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to retrieve posts: {response.status_code} {response.text}")

@app.route('/get_posts')
def fetch_posts():
    if 'access_token' not in session.keys():
        app.logger.error("Access token not found in session")
        return redirect(url_for('login'))
    else:
        try:
            posts = get_posts(access_token=session['access_token'], community='Sztafeta', limit=1)
            return jsonify(posts)
        except Exception as e:
            return str(e), 400
    
@app.route('/sztafeta')
def fetch_athlete_activities():
    if 'access_token' not in session.keys():
        app.logger.error("Access token not found in session")
        print(session.keys())
        return redirect(url_for('login'))
    try:
        access_token = session.get('strava_access_token')
        activities = get_strava_activities(access_token=access_token, per_page=10)
        if activities==[]:
            return render_template("activities.html", error_message="Invalid token", activities=activities)
        return render_template("activities.html", activities=activities)
    except Exception as error:
        strava_auth_url = url_for('sztafeta')
        print("Error:", error)
        return render_template("activities.html", error_message=str(error), strava_auth_url=strava_auth_url)

def get_last_distance():
    url = 'https://api.hejto.pl/posts'
    params = {
        'community': 'Sztafeta',
        'limit': 1
    }
    response = requests.get(url, params=params)

    if response.status_code == 200:
        posts = response.json()
        if posts["_embedded"]["items"]:
            last_post = posts["_embedded"]["items"][0]
            content_plain = last_post.get("content_plain", "")
            
            first_line = unicodedata.normalize("NFKD",content_plain.splitlines()[0])
            
            regex_pattern = r'\b\d{1,3}(?: \d{3})*(?:,\d+)?\b'
            distances = re.findall(regex_pattern, first_line)
            
            if distances:
                # Zwracamy ostatniÄ… liczbÄ™, ktĂłra powinna byÄ‡ dystansem
                distance_str = distances[-1].replace(' ', '') 
                return str(distance_str.replace(',', '.'))  
            else:
                regex_pattern = r'\b\d{1,3}(?: \d{3})*(?:,\d+)?\b'
                for line in content_plain.splitlines():
                    line = unicodedata.normalize("NFKD", line)
                    distances = re.findall(regex_pattern, line)
                    if distances:
                        distance_str = distances[-1].replace(' ', '')
                        return str(distance_str.replace(',', '.'))
        else:
            return None
    else:
        raise Exception(f"Failed to retrieve posts: {response.status_code} {response.text}")


@app.route('/redirect')
def redirect_hejto():
    return redirect("https://www.hejto.pl/spolecznosc/sztafeta")

@app.route('/process_activities', methods=["GET", "POST"])
def process_activities():
    selected_ids = request.form.getlist('selected_activities')
    # strava_activities = json.loads(session.get('strava_activities', '[]'))
    hejto_distance = get_last_distance()
    if hejto_distance is None:
        return "Nie udało się pobrać dystansu z ostatniego postu."
    str_builder = '{:,}'.format(float(hejto_distance)).replace(","," ").replace(".",",")
    total_distance = float(hejto_distance)
    for distance in selected_ids:
        total_distance += float(distance)
        str_builder += " + " + '{:,}'.format(float(distance)).replace(","," ").replace(".",",")
    str_builder += " = " + '{:,}'.format(float(total_distance)).replace(","," ").replace(".",",")

    # czas na pobranie notatek, obrazków
    notes = request.form.get("notes")
    str_builder += f"\n {notes} \n Wpis dodany za pomocą https://hejto.sztafetastat.eu \n #sztafeta #bieganie"
    files = request.files.getlist('files')

    uploaded_file_uuids = []
    i=1
    for file in files:
        if file:
            try:
                image_uuid = upload_image(file)
                uploaded_file_uuids.append({"uuid": image_uuid, "position": i})
                print(image_uuid)
            except Exception as e:
                return str(e)
        i=i+1
    response = create_post(content=str_builder,images=uploaded_file_uuids,nsfw=False)
    if response.status_code == 201:
        return redirect("/redirect")
    else:
        print(f"Failed to create post: {response.status_code} {response.text}")
        raise Exception(f"Failed to create post: {response.status_code} {response.text}")


def upload_image(file):
    url = 'https://api.hejto.pl/uploads'  # Endpoint do uploadu obrazĂłw
    access_token = session['access_token']
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    files = {'image': (file.filename, file, file.content_type)}
    
    response = requests.post(url, headers=headers, files=files)
    
    if response.status_code == 201:
        return response.json().get('uuid')  # UUID otrzymane od Hejto
    else:
        raise Exception(f"Failed to upload image: {response.status_code} {response.text}")



def create_post(content, images=None, nsfw=False):
    try:
        access_token = session['access_token']
        url = 'https://api.hejto.pl/posts'
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        payload = {
            'content': content,
            'images': images or [],
            'nsfw': nsfw,
            'community': "Sztafeta",
            'type': 'discussion'
        }
        response = requests.post(url, headers=headers, json=payload)

        print(f"Response Status Code: {response.status_code}")
        
        # Check if the response has content and try to parse it as JSON
        return response
    
    except Exception as e:
        print(f"Error in create_post: {str(e)}")
        raise


def fetch_sztafeta_posts(access_token, limit=50):
    url = "https://api.hejto.pl/posts"
    params = {
        "community": "Sztafeta",
        "limit": limit
    }
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    
    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    
    return response.json()["_embedded"]["items"]

def extract_distance_from_post(content):
    # regex_pattern = r'\b\d{1,3}(?:[ ]?\d{3})*(?:[,.]\d+)?\b'
    regex_pattern = r'^(\d+[ ,]*\d+[,]*\d+)((?:[ \+]+)(\d+[,]*\d+))+[ =]*(\d+[ ,]*\d+[,]*\d+)'
    naive_pattern = r'\d+ ?\d+,?\d*[+\d ,]+=[+\d ,]+'
    content = unicodedata.normalize("NFKD", content) # remove \xa0
    distances = re.findall(naive_pattern, content)
    # calculated_distance=0.0
    if distances:
        distances_eq = distances[0].split('=')
        distances = distances_eq[0].split('+')
        distances.append(distances_eq[1])
        distances = distances[1:-1]
        for index, distance in enumerate(distances):
            if(distance == ''):
                if index == len(distances) - 1:
                    distances.remove('')
                    return distances
            distances[index] = float(distance.replace(',',".").strip())
        return distances
    else:
        distances = re.findall(naive_pattern, content)
        if distances:
            distance_str = distances[-1].replace(' ', '')
        else:
            return 0.0
        return str(distance_str.replace(',', '.'))
   

def extract_user_distances(posts):
    user_distances = {}
    for post in posts:
        username = post["author"]["username"]
        content = post["content_plain"]
        distances = extract_distance_from_post(content)
        created_at = datetime.strptime(post["created_at"], '%Y-%m-%dT%H:%M:%S%z')

        if username not in user_distances:
            user_distances[username] = []

        user_distances[username].append({"distance": distances, "created_at": created_at})
    return user_distances

def aggregate_distances(user_distances):
    user_aggregated = defaultdict(lambda: {"week": 0.0, "month": 0.0, "year": 0.0, "week_count": 0, "month_count": 0, "year_count": 0, "week_mean": 0.0, "month_mean": 0.0, "year_mean": 0.0})
    user_aggregated = defaultdict(lambda: {"week": 0.0, "month": 0.0, "year": 0.0})
    from datetime import datetime
    now = datetime.now().astimezone()  # Make `now` timezone-aware
    week_start = now - timedelta(days=now.weekday())
    month_start = now.replace(day=1)
    year_start = now.replace(month=1, day=1)

    for username, activities in user_distances.items():
        week_total_distance = 0.0
        month_total_distance = 0.0
        year_total_distance = 0.0
        week_count = 0
        month_count = 0
        year_count = 0
        for activity in activities:
            if activity["created_at"] >= week_start:
                user_aggregated[username]["week"] += sum(activity["distance"])
                week_total_distance += sum(activity["distance"])
                week_count += len(activity["distance"])
            if activity["created_at"] >= month_start:
                user_aggregated[username]["month"] += sum(activity["distance"])
                month_total_distance += sum(activity["distance"])
                month_count += len(activity["distance"])
            if activity["created_at"] >= year_start:
                user_aggregated[username]["year"] += sum(activity["distance"])
                year_total_distance += sum(activity["distance"])
                year_count += len(activity["distance"])
        if week_count > 0:
            user_aggregated[username]["week_mean"] = week_total_distance / week_count
        else:
            user_aggregated[username]["week_mean"] = 0
        if month_count > 0:
            user_aggregated[username]["month_mean"] = month_total_distance / month_count
        else:
            user_aggregated[username]["month_mean"] = 0
        if year_count > 0:
            user_aggregated[username]["year_mean"] = year_total_distance / year_count
        else:
            user_aggregated[username]["year_mean"] = 0
        user_aggregated[username]["week_count"] = week_count
        user_aggregated[username]["month_count"] = month_count
        user_aggregated[username]["year_count"] = year_count
    return user_aggregated

def generate_ranking(user_aggregated):
    ranking = {
        "week": sorted(user_aggregated.items(), key=lambda x: x[1]["week"], reverse=True),
        "month": sorted(user_aggregated.items(), key=lambda x: x[1]["month"], reverse=True),
        "year": sorted(user_aggregated.items(), key=lambda x: x[1]["year"], reverse=True),
    }
    return ranking

@app.route("/ranking")
def ranking():
    if 'access_token' not in session.keys():
        app.logger.error("Access token not found in session")
        print(session.keys())
        return redirect(url_for('login'))

    access_token = session['access_token']

    try:
        sztafeta_posts = fetch_sztafeta_posts(access_token, limit=50)
        user_distances = extract_user_distances(sztafeta_posts)
        user_aggregated = aggregate_distances(user_distances)
        rankings = generate_ranking(user_aggregated)
                # Prepare data for the chart
        monthly_data = defaultdict(float)
        weekly_data = defaultdict(float)
        for username, activities in user_distances.items():
            
            for activity in activities:
                # Extract the activity date and distance
                activity_date = activity['created_at']  # Ensure this is the correct key for the date
                km = activity['distance']  # Ensure this is the correct key for the distance
                
                # Format month and week from the date
                month = activity_date.strftime('%Y-%m')
                week = activity_date.strftime('%Y-%W')
                
                # Update the monthly and weekly data
                monthly_data[month] += sum(km)
                weekly_data[week] += sum(km)

        monthly_data = dict(sorted(monthly_data.items()))
        weekly_data = dict(sorted(weekly_data.items()))
        monthly_labels = list(monthly_data.keys())
        monthly_values = list(monthly_data.values())
        weekly_labels = list(weekly_data.keys())
        weekly_values = list(weekly_data.values())

        # Convert lists to JSON format
        monthly_labels_json = json.dumps(monthly_labels)
        monthly_values_json = json.dumps(monthly_values)
        weekly_labels_json = json.dumps(weekly_labels)
        weekly_values_json = json.dumps(weekly_values)
        print(monthly_labels_json)

        print(monthly_values_json)

        print(weekly_labels_json)

        print(weekly_values_json)

        return render_template('ranking.html', 
                               rankings=rankings,
                               monthly_labels=monthly_labels_json,
                               monthly_data=monthly_values_json,
                               weekly_labels=weekly_labels_json,
                               weekly_data=weekly_values_json)
    except Exception as error:
        app.logger.error(f"Error occurred in /ranking route: {str(error)}")
        return redirect(url_for('login'))

#--------------------- STRAVA ROUTES -----------------------
@app.route('/strava_login')
def strava_login():
    # URL autoryzacyjny Strava
    auth_url = f'https://www.strava.com/oauth/authorize?client_id={STRAVA_CLIENT_ID}&response_type=code&redirect_uri={STRAVA_REDIRECT_URI}&approval_prompt=force&scope=activity:read_all'
    return redirect(auth_url)

@app.route('/strava_callback')
def strava_callback():
    code = request.args.get('code')
    if code:
        try:
            strava_access_token = get_strava_token(code)
            session['strava_access_token'] = strava_access_token
            return redirect('/sztafeta')  # Przekierowanie do endpointu, ktĂłry pobierze dane biegacza
        except Exception as e:
            return str(e), 400
    else:
        return render_template('authorize_strava.html')

def get_strava_token(authorization_code):
    url = 'https://www.strava.com/oauth/token'
    payload = {
        "client_id": STRAVA_CLIENT_ID,
        "client_secret": STRAVA_CLIENT_SECRET,
        "code": authorization_code,
        "grant_type": "authorization_code"
    }
    response = requests.post(url, data=payload)

    if response.status_code == 200:
        token_data = response.json()
        return token_data.get('access_token')
    else:
        raise Exception(f"Failed to retrieve Strava token: {response.status_code} {response.text}")
    

@app.route('/athlete')
def strava_athlete_info():
    strava_access_token = session.get('strava_access_token')
    if strava_access_token:
        try:
            athlete_info = get_strava_athlete(strava_access_token)
            id = athlete_info.get("id")
            athlete_last_stats = get_strava_athlete_last_stats(strava_access_token, id)
            athlete_data = {
            'name': f'{athlete_info.get("firstname")} {athlete_info.get("lastname")}',
            'location': f'{athlete_info.get("city")} {athlete_info.get("country")}',
            'total_activities': athlete_last_stats.get('all_run_totals', {}).get('count', 0),
            'total_distance': round(athlete_last_stats.get('all_run_totals', {}).get('distance', 0) / 1000, 2), # Convert to km
            'last_updated': athlete_info.get('updated_at'),
            'profile_picture': athlete_info.get('profile')
            }
            return render_template('athlete.html', athlete=athlete_data)
        except Exception as e:
            return render_template('authorize_strava.html', error_message=str(e))
    else:
        return render_template('authorize_strava.html')

def get_strava_athlete_last_stats(access_token, id):
    url = f"https://www.strava.com/api/v3/athletes/{id}/stats"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to retrieve athlete data: {response.status_code} {response.text}")

def get_strava_athlete(access_token):
    url = 'https://www.strava.com/api/v3/athlete'
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to retrieve athlete data: {response.status_code} {response.text}") 
    
def get_strava_activities(access_token, per_page=10):
    api_endpoint = 'https://www.strava.com/api/v3/athlete/activities'
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    params = {
        'per_page': per_page
    }
    response = requests.get(api_endpoint, headers=headers, params=params)
    print("Getting activities")
    if response.status_code == 200:
        activities = response.json()
        run_activities = [
            {
                'name': activity['name'],
                'distance_km': round(activity['distance'] / 1000, 2),
                'start_date': activity['start_date_local'][:10]
            }
            for activity in activities
            if activity['type'] == 'Run'
        ]
        return run_activities
    elif response.status_code == 401:
        print("Invalid access token")
        return []
    else:
        raise Exception(f"Failed to retrieve activities: {response.status_code} {response.text}")
            
    # url = 'https://www.strava.com/api/v3/athlete/activities'
    # headers = {
    #     "Authorization": f"Bearer {access_token}"
    # }
    # params = {
    #     "per_page": per_page
    # }
    # response = requests.get(url, headers=headers, params=params)

    # if response.status_code == 200:
    #     activities = response.json()
    #     # Filtrowanie aktywnoĹ›ci do typu 'Run' i konwersja dystansu na kilometry
    #     run_activities = [
    #         {
    #             "name": activity["name"],
    #             "distance_km": round(activity["distance"] / 1000, 2),
    #             "start_date": activity["start_date"]
    #         }
    #         for activity in activities if activity["type"] == "Run"
    #     ]
    #     session['strava_activities'] = json.dumps(run_activities)
    #     return run_activities
    # else:
    #     return render_template('error.html', message=str("failed to retrieve activities")), 400


# error handling

# Custom error handler for 404 Not Found
@app.errorhandler(400)
def not_found_error(error):
    return render_template('error.html', message="Brak tokenu autoryzacyjnego(400)"), 400

@app.errorhandler(401)
def not_found_error(error):
    return render_template('error.html', message="Błąd pobierania danych z hejto.pl(401)"), 400

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error_code=404), 404

# Custom error handler for 500 Internal Server Error
@app.errorhandler(500)
def internal_error(error):
    # You might want to log the error here using logging or another tool
    return render_template('error.html', error_code=500), 500

# General handler for other unhandled exceptions
@app.errorhandler(Exception)
def handle_exception(e):
    return render_template('error.html', message="Nie obsłużony wyjątek!"), 500

if __name__ == '__main__':
    # app.run(debug=True, host='0.0.0.0')
    app.run(debug=True)