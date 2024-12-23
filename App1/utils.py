import requests

def geocode_address(address):
    api_key = 'f95c2a61235f4365a6f22eb79ce8446a'
    url = f'https://api.opencagedata.com/geocode/v1/json?q={address}&key={api_key}'
    response = requests.get(url).json()
    if response['results']:
        latitude = response['results'][0]['geometry']['lat']
        longitude = response['results'][0]['geometry']['lng']
        return latitude, longitude
    return None, None



import math

def haversine(lat1, lon1, lat2, lon2):
    # Radius of the Earth in kilometers
    R = 6371.0

    # Convert latitude and longitude from degrees to radians
    lat1_rad = math.radians(lat1)
    lon1_rad = math.radians(lon1)
    lat2_rad = math.radians(lat2)
    lon2_rad = math.radians(lon2)

    # Differences in coordinates
    dlat = lat2_rad - lat1_rad
    dlon = lon2_rad - lon1_rad

    # Haversine formula
    a = math.sin(dlat / 2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    # Distance in kilometers
    distance = R * c
    return distance

# Example usage
lat1, lon1 = 40.757261, -73.985899  # Times Square, New York
lat2, lon2 = 28.704060, 77.102493  # Delhi, India

distance = haversine(lat1, lon1, lat2, lon2)
print(f"Distance: {distance} km")
