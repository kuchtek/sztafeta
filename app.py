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
from flask import flash
from microservice import HejtoDataCollector

#----------------------- APP CONFIG -----------------------
app = Flask(__name__)
app.logger.addHandler(logging.StreamHandler())
app.logger.setLevel(logging.INFO)
load_dotenv()
app.secret_key = os.environ.get('FLASK_SECRET_KEY')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
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
        'current_date': '2025',
        'app_version': '0.4'
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
    authorization_code = request.args.get("code")
    if not authorization_code:
        raise Exception("Authorization code not provided", 400)
    app.logger.info("Within /callback")
    if 'access_token' in session:
        return(redirect(url_for('fetch_athlete_activities')))

    app.logger.info("Within /callback, generating authorization code")
    
    try:
        app.logger.info("Getting hejto token")
        token,refresh_token = get_hejto_token(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            authorization_code=authorization_code
        )
        session['access_token'] = token
        session['refresh_token'] = refresh_token
        session.permanent = True
        app.logger.info("Got hejto token and saved to session")
        return render_template('authorize_strava.html')
    except Exception:
        auth_url = generate_authorization_url()
        return redirect(auth_url)

def refresh_session_token():
    if 'refresh_token' in session:
        try:
            app.logger.info("Refreshing session token")
            token, refresh_token = get_hejto_token(
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                grant_type='refresh_token',
                refresh_token=session['refresh_token']
            )
            app.logger.info("Got new session token")
            session['access_token'] = token
            session['refresh_token'] = refresh_token  
            session.permanent = True
            return True
        except Exception as e:
            app.logger.error("Failed to refresh session token: {}".format(e))
    return False

# @app.before_request
# def check_session_token():
#     if 'access_token' not in session or session['access_token'] is None:
#         if not refresh_session_token():
#             auth_url = generate_authorization_url()
#             return redirect(auth_url), 302

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
        return token_data.get('access_token'), token_data.get('refresh_token')
    else:
        app.logger.error("Something goes wrong")
        raise Exception(f"Failed to retrieve token: {response.status_code} {response.text}")
    
@app.route('/activity/<string:activity_type>')
@app.route('/activity/')
def fetch_athlete_activities(activity_type=None):
    app.logger.debug("Activity type: {}".format(activity_type))
    if 'access_token' not in session.keys():
        app.logger.error("Access token not found in session")
        print(session.keys())
        return redirect(url_for('login'))
    if activity_type == None:
        app.logger.debug("nic tu nie ma")
        return redirect('/athlete')
    if activity_type not in ['sztafeta','rownik', 'spacer', 'pompuj', 'medytacja']:
        return render_template("activities.html", error_message="Invalid activity type", activities=[])
    try:
        access_token = session.get('strava_access_token')
        activities = get_strava_activities(access_token=access_token, per_page=10, activity_type=activity_type)
        return render_template("activities.html", activities=activities, activity_type=activity_type)
    except Exception as error:
        strava_auth_url = url_for('activity')
        print("Error:", error)
        return render_template("activities.html", error_message=str(error), strava_auth_url=strava_auth_url)

@app.route('/activity/sztafeta')
def fetch_run_activities():
    return fetch_athlete_activities('sztafeta')

@app.route('/activity/rownik')
def fetch_ride_activities():
    return fetch_athlete_activities('rownik')

@app.route('/activity/spacer')
def fetch_walk_activities():
    return fetch_athlete_activities('spacer')

@app.route('/activity/pompuj')
def fetch_pump_activities():
    return fetch_athlete_activities('pompuj')

@app.route('/activity/medytacja')
def fetch_meditation_activities():
    return fetch_athlete_activities('medytacja')

@app.route('/last_distance/<string:community>')
def get_last_distance_from_community(community):
    return get_last_distance(community=community)

def get_last_distance(community):
    app.logger.info("Getting last distance..")
    url = 'https://api.hejto.pl/posts'
    params = {
        'community': community,
        'limit': 5
    }
    
    # Special handling for #pompujwpoprzekziemi tag
    if community == 'sport':
        params = {
            'tags[]': 'pompujwpoprzekziemi',
            'limit': 5
        }
    app.logger.info(params)
    response = requests.get(url, params=params)
    if response.status_code == 200:
        posts = response.json()
        if posts["_embedded"]["items"]:
            for post in posts["_embedded"]["items"]:
                content_plain = post.get("content_plain", "")
                app.logger.info("Get Content plain: " + content_plain)
                first_line = unicodedata.normalize("NFKD", content_plain.splitlines()[0])
                app.logger.info("Get first line: " + first_line)
                # Check if the line matches the required format
                
                regex_pattern = r'\b\d+(?: \d{3})*(?:,\d+)?\b'
                distances = re.findall(regex_pattern, first_line)
                if distances:
                    distance_str = distances[-1].replace(' ', '')
                    return str(distance_str.replace(',', '.'))

                # If first line doesn't match, try other lines
                for line in content_plain.splitlines():
                    line = unicodedata.normalize("NFKD", line)
                    if community in ['sport', 'rozwoj']:
                        if community == 'sport':
                            match = re.match(r'^\s*(\d+(?:[ ]\d{3})*(?:[.,]\d+)?)\s*(?:\+\s*\d+(?:[ ]\d{3})*(?:[.,]\d+)?)*\s*=\s*\d+(?:[ ]\d{3})*(?:[.,]\d+)?\s*$', line)
                        else:
                            match = re.match(r'^\s*(\d+(?:[ ]\d{3})*(?:[.,]\d+)?)\s*(?:-\s*\d+(?:[ ]\d{3})*(?:[.,]\d+)?)*\s*=\s*\d+(?:[ ]\d{3})*(?:[.,]\d+)?\s*$', line)
                        if match:
                            initial_number = match.group(1)
                            return str(initial_number.replace(' ', '').replace(',', '.'))
                    else:
                        regex_pattern = r'\b\d{1,3}(?: \d{3})*(?:,\d+)?\b'
                        distances = re.findall(regex_pattern, line)
                        if distances:
                            distance_str = distances[-1].replace(' ', '')
                            return str(distance_str.replace(',', '.'))
    return None

@app.route('/process_activities', methods=["GET", "POST"])
def process_activities():
    app.logger.info("Within /process_activities")
    activity_type = request.form.get('activity_type')
    app.logger.info(activity_type)
    communities = {
        'sztafeta': 'Sztafeta',
        'rownik': 'rowerowy-rownik',
        'spacer': 'ksiezycowy-spacer',
        'pompuj': 'sport',
        'medytacja': 'rozwoj'
    }
    tag_communities = {
        'sztafeta': '#sztafeta #bieganie',
        'rownik': '#rowerowyrownik',
        'spacer': '#ksiezycowyspacer',
        'pompuj': '#pompujwpoprzekziemi',
        'medytacja': '#rokmedytacji'
    }
    tag_community = tag_communities[activity_type]
    community = communities[activity_type]
    selected_ids = request.form.getlist('selected_activities')
    app.logger.debug(selected_ids)
    if len(selected_ids) == 0:
        flash("Zaznacz przynajmniej jedną aktywność", "danger")
        return render_template('activities.html')
    if len(selected_ids) == 1 and selected_ids[0] == '0':
        flash("Dystans musi być większy niż 0", "danger")
        return render_template('activities.html')
    app.logger.info("Getting last distance")
    hejto_distance = get_last_distance(community=community)
    app.logger.info(hejto_distance)
    if hejto_distance is None:
        return "Nie udało się pobrać dystansu z ostatniego postu."
    total_distance = round(float(hejto_distance)) if community=='rowerowy-rownik' else round(float(hejto_distance), 2)
    str_builder = '{:,}'.format(total_distance).replace(","," ").replace(".",",")
    for distance in selected_ids:
        app.logger.debug("Distance: " + distance)
        distance = round(float(distance), 2)
        if(community in ['sport', 'rozwoj', 'ksiezycowy-spacer']):
            total_distance -= distance
        else:
            if(community=='rowerowy-rownik'):
                distance = round(distance)
                total_distance += distance
                total_distance = round(total_distance)
            else:
                total_distance += distance
        str_builder += " + " + '{:,}'.format(distance).replace(","," ").replace(".",",")
        app.logger.debug("Current str: " + str_builder)
    total_distance = round(total_distance, 2)
    str_builder += " = " + "{:,}".format(total_distance).replace(","," ").replace(".",",")
    app.logger.debug("Total distance: " + str(total_distance))
    # czas na pobranie notatek, obrazków
    notes = request.form.get("notes")
    str_builder += f"\n {notes} \n Wpis dodany za pomocą https://hejto.sztafetastat.eu \n {tag_community}"
    if(community in ['ksiezycowy-spacer', 'sport', 'rozwoj']):
        str_builder = str_builder.replace('+','-')
    files = request.files.getlist('files')
    app.logger.debug(str_builder)
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
    # return str_builder
    response = create_post(content=str_builder,images=uploaded_file_uuids,nsfw=False, community=community)
    if response.status_code == 201:
        return redirect(f"https://www.hejto.pl/spolecznosc/{community}")
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



def create_post(content, images=None, nsfw=False, community='sztafeta'):
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
            'community': community,
            'type': 'discussion'
        }
        response = requests.post(url, headers=headers, json=payload)
        app.logger.info(f"Response Status Code: {response.status_code}")
        print(f"Response Status Code: {response.status_code}")
        
        # Check if the response has content and try to parse it as JSON
        return response
        # return payload
    
    except Exception as e:
        print(f"Error in create_post: {str(e)}")
        app.logger.info(f"Error in create_post: {str(e)}")
        raise


def fetch_community_posts(access_token, limit=50, community=None):
    if community is None:
        render_template("error.html", error_code=404, error_msg="Nie znaleziono strony")
    url = "https://api.hejto.pl/posts"
    params = {
        "community": community,
        "limit": limit
    }
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    
    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    
    return response.json()["_embedded"]["items"]

def extract_distance_from_post(content):
    content = unicodedata.normalize("NFKD", content) # remove \xa0
    app.logger.debug(content)
    # calculated_distance=0.0
    content = re.sub(r'^\d{1,3}(?:[ ]\d{3})*(?:[.,]\d+)?\s*', '', content)
    content = re.sub(r'\s*=\s*.*$', '', content)
    pattern = re.compile(r'[+-]\s*(\d{1,3}(?:[ ]\d{3})*(?:[.,]\d+)?)')
    matches = pattern.findall(content)
    distances = [float(num.replace(' ', '').replace(',', '.')) for num in matches]
    app.logger.debug(distances)
    return distances

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
    # user_aggregated = defaultdict(lambda: {"week": 0.0, "month": 0.0, "year": 0.0})
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
            app.logger.debug(activity)
            if not isinstance(activity['distance'], list):
                activity['distance'] = [activity['distance']]
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

@app.route('/ranking/<string:community>')
def ranking(community):
    collector = HejtoDataCollector()
    
    overall_stats = collector.get_overall_stats()
    current_week_stats = collector.get_current_week_stats()
    current_month_stats = collector.get_current_month_stats()
    monthly_stats = collector.get_monthly_community_stats()
    
    return render_template('ranking.html',
                         overall_stats=overall_stats,
                         current_week_stats=current_week_stats,
                         current_month_stats=current_month_stats,
                         monthly_stats=monthly_stats)

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
            return redirect('/athlete')  # Przekierowanie do endpointu, ktĂłry pobierze dane biegacza
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
    
def get_strava_activities(access_token, per_page=10, activity_type='sztafeta'):
    api_endpoint = 'https://www.strava.com/api/v3/athlete/activities'
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    params = {
        'per_page': per_page
    }
    activity_types = {
        'sztafeta': 'Run',
        'rownik': 'Ride',
        'spacer': 'Walk'
    }
    response = requests.get(api_endpoint, headers=headers, params=params)
    print("Getting activities")
    if response.status_code == 200:
        activities = response.json()
        filtered_activities = [
            {
                'name': activity['name'],
                'distance_km': round(activity['distance'] / 1000, 2),
                'start_date': activity['start_date_local'][:10]
            }
            for activity in activities
            if activity['type'] == activity_types[activity_type]
        ]
        return filtered_activities
    elif response.status_code == 401:
        print("Invalid access token")
        return []
    else:
        raise Exception(f"Failed to retrieve activities: {response.status_code} {response.text}")

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

# General monitoring block
@app.route('/ping')
def ping():
    return 'pong'

if __name__ == '__main__':
    app.run(host='0.0.0.0')
    # app.run(debug=True)